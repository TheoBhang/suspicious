"""Policy proxy between Cortex and the Docker socket proxy.

tecnativa/docker-socket-proxy filters by path and method only, so a compromised
Cortex can still POST /containers/create with Privileged or a bind of "/". This
service sits in front of it, reads the body of container create and image pull
requests and applies an allow-list:

  * the image must come from the analyzer catalogs (or DOCKER_POLICY_EXTRA_IMAGES);
  * no Privileged, no added capabilities, devices, host namespaces, host network,
    unconfined security options, named volumes or Mounts;
  * every bind source must sit inside the Cortex job directory;
  * only the endpoints an analyzer run needs are reachable.

DOCKER_POLICY_MODE=log (default) forwards everything and logs what it would have
refused; DOCKER_POLICY_MODE=enforce answers 403. Standard library only.
"""
import asyncio
import dataclasses
import json
import os
import posixpath
import re
import sys
import urllib.parse

MAX_BODY = 1 << 20
CID = r"[A-Za-z0-9][A-Za-z0-9_.-]*"
ENDPOINTS = [  # (method, path regex): everything an analyzer run uses, nothing else
    ("GET", r"/_ping"), ("HEAD", r"/_ping"), ("GET", r"/info"), ("GET", r"/version"),
    ("GET", r"/images/json"), ("POST", r"/images/create"), ("POST", r"/containers/create"),
    ("GET", rf"/containers/{CID}/json"), ("POST", rf"/containers/{CID}/start"),
    ("POST", rf"/containers/{CID}/wait"), ("GET", rf"/containers/{CID}/logs"),
    ("POST", rf"/containers/{CID}/stop"), ("POST", rf"/containers/{CID}/kill"),
    ("DELETE", rf"/containers/{CID}"),
]
EMPTY = (None, "", [], {}, False, 0)


def normalise_image(name):
    if "@" in name or ":" in name.rsplit("/", 1)[-1]:
        return name
    return f"{name}:latest"


def load_allowed_images(paths, extra=()):
    """dockerImage values of Cortex analyzer catalogs (a list, or {"analyzers": [...]})."""
    images = {normalise_image(i) for i in extra if i}
    for path in paths:
        try:
            with open(path) as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            log("catalog_unreadable", path=path, error=str(exc))
            continue
        entries = data.get("analyzers", []) if isinstance(data, dict) else data
        for entry in entries:
            if isinstance(entry, dict) and entry.get("dockerImage"):
                images.add(normalise_image(entry["dockerImage"]))
    return images


def _bind_problem(bind, job_dir):
    if not isinstance(bind, str):
        return f"Binds entry {bind!r} is not a string"
    source = bind.split(":", 1)[0]
    if not source.startswith("/"):
        return f"bind {bind!r} is not a host path (named volumes are refused)"
    norm = posixpath.normpath(source)
    root = posixpath.normpath(job_dir)
    if norm != root and not norm.startswith(root + "/"):
        return f"bind source {source!r} is outside the job directory {root}"
    return None


def evaluate_create(body, images, job_dir):
    """Reasons a container create body is refused (empty list: allowed)."""
    if not isinstance(body, dict):
        return ["create body is not a JSON object"]
    problems = []
    image = body.get("Image")
    if not isinstance(image, str) or normalise_image(image) not in images:
        problems.append(f"image {image!r} is not in the analyzer catalogs")
    host = body.get("HostConfig") or {}
    if not isinstance(host, dict):
        return problems + ["HostConfig is not an object"]
    if host.get("Privileged"):
        problems.append("Privileged is set")
    for field in ("CapAdd", "Devices", "DeviceRequests", "Mounts", "VolumesFrom", "Sysctls",
                  "PortBindings", "CgroupParent", "PidMode", "IpcMode", "UsernsMode", "UTSMode"):
        if host.get(field) not in EMPTY:
            problems.append(f"HostConfig.{field} is set")
    network = host.get("NetworkMode") or ""
    if network == "host" or network.startswith("container:"):
        problems.append(f"NetworkMode {network!r} is refused")
    if host.get("Runtime") not in (None, "", "runc"):
        problems.append(f"Runtime {host['Runtime']!r} is refused")
    for opt in host.get("SecurityOpt") or []:
        if "unconfined" in str(opt).lower() or "disable" in str(opt).lower():
            problems.append(f"SecurityOpt {opt!r} weakens confinement")
    binds = host.get("Binds") or []
    for bind in binds if isinstance(binds, list) else [binds]:
        problem = _bind_problem(bind, job_dir)
        if problem:
            problems.append(problem)
    return problems


def evaluate_request(method, path, query, body, images, job_dir):
    """Reasons a request is refused (empty list: allowed). `path` may carry /vX.YY."""
    path = re.sub(r"^/v\d+(\.\d+)?(?=/)", "", path)
    if ".." in path or "//" in path:
        return [f"path {path!r} is not normal"]
    if not any(method == m and re.fullmatch(p, path) for m, p in ENDPOINTS):
        return [f"{method} {path} is not an endpoint analyzer runs use"]
    if path == "/containers/create":
        return evaluate_create(body, images, job_dir)
    if path == "/images/create":
        args = urllib.parse.parse_qs(query)
        if args.get("fromSrc"):
            return ["image import (fromSrc) is refused"]
        name = (args.get("fromImage") or [""])[0]
        tag = (args.get("tag") or [""])[0]
        image = normalise_image(f"{name}:{tag}" if tag and ":" not in name else name)
        if image not in images:
            return [f"pulling {image!r}: not in the analyzer catalogs"]
    return []


def log(event, **fields):
    print(json.dumps({"event": event, **fields}), flush=True)


def summarise_create(body):
    if not isinstance(body, dict):
        return {"body": "not an object"}
    keep = {k: body[k] for k in ("Image", "User", "WorkingDir", "Entrypoint") if k in body}
    keep["TopLevelKeys"] = sorted(body)
    keep["EnvNames"] = sorted(e.split("=", 1)[0] for e in body.get("Env") or [] if isinstance(e, str))
    keep["HostConfig"] = body.get("HostConfig")
    return keep


@dataclasses.dataclass
class Config:
    mode: str
    upstream_host: str
    upstream_port: int
    job_dir: str
    images: set


async def read_chunked(reader):
    data = b""
    while True:
        size = int((await reader.readline()).split(b";")[0].strip() or b"0", 16)
        if size == 0:
            while (await reader.readline()).strip():  # trailers
                pass
            return data
        data += await reader.readexactly(size)
        await reader.readexactly(2)
        if len(data) > MAX_BODY:
            raise ValueError("body too large")


async def refuse(writer, status, reason):
    text = json.dumps({"message": f"docker policy: {reason}"}).encode()
    phrase = {400: "Bad Request", 403: "Forbidden"}[status]
    writer.write(f"HTTP/1.1 {status} {phrase}\r\nContent-Type: application/json\r\n"
                 f"Content-Length: {len(text)}\r\nConnection: close\r\n\r\n".encode() + text)
    await writer.drain()


async def pipe(src, dst):
    try:
        while chunk := await src.read(65536):
            dst.write(chunk)
            await dst.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass


async def handle(reader, writer, cfg):
    up_writer = None
    try:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            return
        lines = head[:-4].decode("latin-1").split("\r\n")
        try:
            method, target, version = lines[0].split(" ", 2)
        except ValueError:
            return await refuse(writer, 400, "bad request line")
        headers = [tuple(h.split(":", 1)) for h in lines[1:] if ":" in h]
        names = {k.strip().lower(): v.strip() for k, v in headers}
        url = urllib.parse.urlsplit(target)
        upgrade = "upgrade" in names.get("connection", "").lower()
        body = b""
        try:
            if "chunked" in names.get("transfer-encoding", "").lower():
                body = await read_chunked(reader)
            elif int(names.get("content-length") or 0):
                if int(names["content-length"]) > MAX_BODY:
                    return await refuse(writer, 400, "body too large")
                body = await reader.readexactly(int(names["content-length"]))
        except (ValueError, asyncio.IncompleteReadError):
            return await refuse(writer, 400, "unreadable request body")

        parsed = None
        if method == "POST" and re.sub(r"^/v\d+(\.\d+)?", "", url.path) == "/containers/create":
            try:
                parsed = json.loads(body or b"null")
            except ValueError:
                parsed = None
        problems = evaluate_request(method, url.path, url.query, parsed, cfg.images, cfg.job_dir)
        verdict = "allow" if not problems else ("deny" if cfg.mode == "enforce" else "would_deny")
        fields = {"method": method, "path": url.path, "verdict": verdict, "problems": problems}
        if url.path.endswith("/containers/create"):
            fields["create"] = summarise_create(parsed)
        log("request", **fields)
        if verdict == "deny":
            return await refuse(writer, 403, "; ".join(problems))

        skip = {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "content-length"}
        out = [lines[0]] + [f"{k}:{v}" for k, v in headers if k.strip().lower() not in skip
                            and not (upgrade and k.strip().lower() == "connection")]
        out.append("Connection: Upgrade" if upgrade else "Connection: close")
        if body:
            out.append(f"Content-Length: {len(body)}")
        up_reader, up_writer = await asyncio.open_connection(cfg.upstream_host, cfg.upstream_port)
        up_writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + body)
        await up_writer.drain()
        pump = asyncio.create_task(pipe(reader, up_writer))
        await pipe(up_reader, writer)
        pump.cancel()
    except OSError as exc:
        log("upstream_error", error=str(exc))
    finally:
        for w in (up_writer, writer):
            if w is not None:
                w.close()


async def serve():
    mode = os.environ.get("DOCKER_POLICY_MODE", "log")
    if mode not in ("log", "enforce"):
        sys.exit(f"DOCKER_POLICY_MODE must be log or enforce, not {mode!r}")
    host, _, port = os.environ.get("DOCKER_POLICY_UPSTREAM", "docker-proxy-upstream:2375").partition(":")
    catalogs = [p for p in os.environ.get("DOCKER_POLICY_CATALOGS", "").split(",") if p]
    extra = [i for i in os.environ.get("DOCKER_POLICY_EXTRA_IMAGES", "").split(",") if i]
    cfg = Config(mode, host, int(port or 2375), os.environ["DOCKER_POLICY_JOB_DIR"],
                 load_allowed_images(catalogs, extra))
    server = await asyncio.start_server(lambda r, w: handle(r, w, cfg), "0.0.0.0", 2375, limit=1 << 16)
    log("started", mode=mode, upstream=f"{host}:{cfg.upstream_port}", job_dir=cfg.job_dir,
        images=len(cfg.images))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(serve())
