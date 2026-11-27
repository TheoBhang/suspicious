"""Policy proxy between Cortex and the Docker socket proxy.

tecnativa/docker-socket-proxy filters by path and method only, so a compromised
Cortex can still POST /containers/create with Privileged or a bind of "/". This
service sits in front of it, reads the body of container create and image pull
requests and applies an allow-list:

  * the image must come from the analyzer catalogs (or DOCKER_POLICY_EXTRA_IMAGES);
  * no Privileged, no added capabilities, devices, host namespaces, unconfined security options,
    named volumes or Mounts, and only the default network (default, bridge or none): a container
    on a user network could reach the socket proxy itself;
  * every bind source must be a directory inside the Cortex job directory (not the directory itself);
  * only the endpoints an analyzer run needs are reachable, one request per connection, no upgrades.

Docker decodes JSON keys case-insensitively (with Unicode folding) and lets the last duplicate win, so the
body is parsed strictly: a key repeated in any case, or a non-ASCII key, is refused, and every key is
compared in lower case. HostConfig is an allow-list of the fields an analyzer run needs. A create gets a
label, and start, stop, kill, wait, logs, inspect and delete only reach containers that carry it, so a
compromised Cortex cannot read or stop the stack's own containers. Only a create may carry a body.

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
READ_TIMEOUT = 15   # seconds to read one request (head and body)
LABEL = "org.thalesgroup.suspicious.cortex-analyzer"
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


def parse_json(raw):
    """json.loads that refuses a key repeated in any case (Docker's decoder is case-insensitive)."""
    def pairs(items):
        seen = set()
        for key, _ in items:
            if not key.isascii():   # Go folds e.g. U+017F onto "s"; no Docker field has a non-ASCII name
                raise ValueError(f"key {key!r} is not ASCII")
            low = key.lower()
            if low in seen:
                raise ValueError(f"key {key!r} is repeated")
            seen.add(low)
        return dict(items)
    return json.loads(raw, object_pairs_hook=pairs)


def _fold(obj):
    """Lower-case every key, so a field cannot hide behind its spelling."""
    if isinstance(obj, dict):
        return {k.lower(): _fold(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fold(v) for v in obj]
    return obj


def normalise_image(name):
    if "@" in name or ":" in name.rsplit("/", 1)[-1]:
        return name
    return f"{name}:latest"


def load_allowed_images(paths, extra=(), strict=False):
    """dockerImage values of Cortex analyzer catalogs (a list, or {"analyzers": [...]}).
    strict: an unreadable catalog, or no image at all, raises ValueError (the service then exits)."""
    images = {normalise_image(i) for i in extra if i}
    for path in paths:
        try:
            with open(path) as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            if strict:
                raise ValueError(f"catalog {path} is unreadable: {exc}") from exc
            log("catalog_unreadable", path=path, error=str(exc))
            continue
        entries = data.get("analyzers", []) if isinstance(data, dict) else data
        for entry in entries:
            if isinstance(entry, dict) and entry.get("dockerImage"):
                images.add(normalise_image(entry["dockerImage"]))
    if strict and not images:
        raise ValueError("no analyzer image in the catalogs: every create and pull would be refused")
    return images


def _bind_problem(bind, job_dir):
    if not isinstance(bind, str):
        return f"Binds entry {bind!r} is not a string"
    source = bind.split(":", 1)[0]
    if not source.startswith("/"):
        return f"bind {bind!r} is not a host path (named volumes are refused)"
    root = posixpath.normpath(job_dir)
    if not posixpath.normpath(source).startswith(root + "/"):
        return f"bind source {source!r} is not a directory inside the job directory {root}"
    # Resolve symlinks too (the policy container mounts the job directory read-only at the same path):
    # a link created inside the job directory must not point the bind somewhere else.
    if not os.path.realpath(source).startswith(os.path.realpath(root) + "/"):
        return f"bind source {source!r} resolves outside the job directory {root}"
    return None


DANGEROUS_FIELDS = ("CapAdd", "Devices", "DeviceRequests", "Mounts", "VolumesFrom", "Sysctls",
                    "PortBindings", "CgroupParent", "PidMode", "IpcMode", "UsernsMode", "UTSMode")
SAFE_NETWORKS = ("", "default", "bridge", "none")
# What an analyzer run sends (the dev run showed only Binds) plus plain resource limits. Anything else
# with a value is refused; the fields below are judged on their own.
ALLOWED_HOSTCONFIG = {"binds", "networkmode", "autoremove", "capdrop", "memory", "memoryswap",
                      "memoryreservation", "nanocpus", "cpushares", "cpuperiod", "cpuquota",
                      "cpusetcpus", "pidslimit", "readonlyrootfs", "init", "ulimits"}
JUDGED_ELSEWHERE = {"privileged", "runtime", "securityopt"}
UNMASKING = ("maskedpaths", "readonlypaths")   # an empty list here removes the default masking


def evaluate_create(body, images, job_dir):
    """Reasons a container create body is refused (empty list: allowed)."""
    if not isinstance(body, dict):
        return ["create body is not a JSON object (or repeats a key)"]
    body = _fold(body)
    problems = []
    image = body.get("image")
    if not isinstance(image, str) or normalise_image(image) not in images:
        problems.append(f"image {image!r} is not in the analyzer catalogs")
    host = body.get("hostconfig") or {}
    if not isinstance(host, dict):
        return problems + ["HostConfig is not an object"]
    if host.get("privileged"):
        problems.append("Privileged is set")
    for field in DANGEROUS_FIELDS:
        if host.get(field.lower()) not in EMPTY:
            problems.append(f"HostConfig.{field} is set")
    network = host.get("networkmode") or ""
    if network not in SAFE_NETWORKS:
        problems.append(f"NetworkMode {network!r} is refused (only default, bridge or none)")
    if host.get("runtime") not in (None, "", "runc"):
        problems.append(f"Runtime {host['runtime']!r} is refused")
    for opt in host.get("securityopt") or []:
        if "unconfined" in str(opt).lower() or "disable" in str(opt).lower():
            problems.append(f"SecurityOpt {opt!r} weakens confinement")
    for field in UNMASKING:
        if host.get(field) is not None:
            problems.append(f"HostConfig.{field} is set")
    for field, value in host.items():
        if (value not in EMPTY and field not in ALLOWED_HOSTCONFIG and field not in JUDGED_ELSEWHERE
                and field not in {f.lower() for f in DANGEROUS_FIELDS}):
            problems.append(f"HostConfig.{field} is not an allowed field")
    networking = body.get("networkingconfig")
    if isinstance(networking, dict) and networking.get("endpointsconfig") not in EMPTY:
        problems.append("NetworkingConfig.EndpointsConfig attaches networks: refused")
    binds = host.get("binds") or []
    for bind in binds if isinstance(binds, list) else [binds]:
        problem = _bind_problem(bind, job_dir)
        if problem:
            problems.append(problem)
    return problems


def evaluate_request(method, path, query, body, images, job_dir, raw_body=b"", content_type=""):
    """Reasons a request is refused (empty list: allowed). `path` may carry /vX.YY."""
    path = re.sub(r"^/v\d+(\.\d+)?(?=/)", "", path)
    if ".." in path or "//" in path:
        return [f"path {path!r} is not normal"]
    if not any(method == m and re.fullmatch(p, path) for m, p in ENDPOINTS):
        return [f"{method} {path} is not an endpoint analyzer runs use"]
    if path != "/containers/create" and raw_body:
        # The daemon merges a form-encoded POST body into the query, ahead of it: a body could change
        # what the checks below saw (for example fromImage).
        return [f"{method} {path} must not carry a body"]
    if path == "/containers/create":
        if "x-www-form-urlencoded" in content_type.lower():
            return ["create must be JSON, not a form"]
        return evaluate_create(body, images, job_dir)
    if path == "/images/create":
        args = urllib.parse.parse_qs(query)
        if args.get("fromSrc"):
            return ["image import (fromSrc) is refused"]
        name = (args.get("fromImage") or [""])[0]
        tag = (args.get("tag") or [""])[0]
        own_tag = name.rsplit("/", 1)[-1].partition(":")[2]
        if tag and ("@" in name or (own_tag and own_tag != tag)):
            return [f"pull of {name!r} with a different tag {tag!r}"]   # Docker would pull the tag
        image = normalise_image(f"{name}:{tag}" if tag and not own_tag else name)
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
        field = (await asyncio.wait_for(reader.readline(), READ_TIMEOUT)).split(b";")[0].strip()
        size = int(field, 16)   # an empty or non-hex size line raises ValueError
        if size == 0:
            while (await asyncio.wait_for(reader.readline(), READ_TIMEOUT)).strip():  # trailers
                pass
            return data
        if size > MAX_BODY - len(data):
            raise ValueError("body too large")
        data += await asyncio.wait_for(reader.readexactly(size), READ_TIMEOUT)
        await asyncio.wait_for(reader.readexactly(2), READ_TIMEOUT)


async def refuse(writer, status, reason):
    text = json.dumps({"message": f"docker policy: {reason}"}).encode()
    phrase = {400: "Bad Request", 403: "Forbidden"}[status]
    try:
        writer.write(f"HTTP/1.1 {status} {phrase}\r\nContent-Type: application/json\r\n"
                     f"Content-Length: {len(text)}\r\nConnection: close\r\n\r\n".encode() + text)
        await writer.drain()
    except ConnectionError:   # the client already left: nothing to tell it
        pass


CONTAINER_PATH = re.compile(rf"/containers/({CID})(?:/[a-z]+)?")


async def owned(cfg, cid):
    """True when the container carries our label, or does not exist (nothing to protect). The label is
    read from the daemon through the upstream proxy, so it survives a restart of this service."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(cfg.upstream_host, cfg.upstream_port), READ_TIMEOUT)
        # HTTP/1.0: the daemon then answers with a Content-Length body and no chunked framing to decode.
        writer.write(f"GET /containers/{cid}/json HTTP/1.0\r\nHost: docker\r\n\r\n".encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(MAX_BODY), READ_TIMEOUT)
        writer.close()
        head, _, body = raw.partition(b"\r\n\r\n")
        status = int(head.split(b" ", 2)[1])
        if status == 404:
            return True
        if status != 200:
            return False
        labels = ((json.loads(body).get("Config") or {}).get("Labels")) or {}
        return labels.get(LABEL) == "1"
    except (OSError, ValueError, IndexError, asyncio.TimeoutError):
        return False   # cannot tell: refuse


def label_create(parsed):
    """The create body with our label added (any spelling of the Labels key is replaced by it)."""
    out = {k: v for k, v in parsed.items() if k.lower() != "labels"}
    old = next((v for k, v in parsed.items() if k.lower() == "labels"), None)
    out["Labels"] = {**(old if isinstance(old, dict) else {}), LABEL: "1"}
    return out


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
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), READ_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            return await refuse(writer, 400, "request head not received")
        lines = head[:-4].decode("latin-1").split("\r\n")
        try:
            method, target, version = lines[0].split(" ", 2)
        except ValueError:
            return await refuse(writer, 400, "bad request line")
        headers = [tuple(h.split(":", 1)) for h in lines[1:] if ":" in h]
        names = {k.strip().lower(): v.strip() for k, v in headers}
        url = urllib.parse.urlsplit(target)
        if "upgrade" in names.get("connection", "").lower() or "upgrade" in names:
            log("request", method=method, path=url.path, verdict="deny", problems=["upgrade is refused"])
            return await refuse(writer, 403, "connection upgrades are refused")
        body = b""
        try:
            if "chunked" in names.get("transfer-encoding", "").lower():
                body = await read_chunked(reader)
            elif int(names.get("content-length") or 0):
                if int(names["content-length"]) > MAX_BODY:
                    return await refuse(writer, 400, "body too large")
                body = await asyncio.wait_for(reader.readexactly(int(names["content-length"])), READ_TIMEOUT)
        except (ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            return await refuse(writer, 400, "unreadable request body")

        parsed = None
        if method == "POST" and re.sub(r"^/v\d+(\.\d+)?", "", url.path) == "/containers/create":
            try:
                parsed = parse_json(body or b"null")
            except ValueError:
                parsed = None
        problems = evaluate_request(method, url.path, url.query, parsed, cfg.images, cfg.job_dir,
                                    raw_body=body, content_type=names.get("content-type", ""))
        match = CONTAINER_PATH.fullmatch(re.sub(r"^/v\d+(\.\d+)?", "", url.path))
        if not problems and match and match.group(1) != "create" and not await owned(cfg, match.group(1)):
            problems = [f"container {match.group(1)!r} was not created through this policy"]
        verdict = "allow" if not problems else ("deny" if cfg.mode == "enforce" else "would_deny")
        fields = {"method": method, "path": url.path, "verdict": verdict, "problems": problems}
        if url.path.endswith("/containers/create"):
            fields["create"] = summarise_create(parsed)
        log("request", **fields)
        if verdict == "deny":
            return await refuse(writer, 403, "; ".join(problems))
        if re.sub(r"^/v\d+(\.\d+)?", "", url.path) == "/containers/create" and isinstance(parsed, dict):
            body = json.dumps(label_create(parsed)).encode()   # forwarded in log mode too, so containers
                                                                # made before enforce stay manageable

        skip = {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "content-length"}
        out = [lines[0]] + [f"{k}:{v}" for k, v in headers if k.strip().lower() not in skip]
        out.append("Connection: close")
        if body:
            out.append(f"Content-Length: {len(body)}")
        up_reader, up_writer = await asyncio.open_connection(cfg.upstream_host, cfg.upstream_port)
        up_writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + body)
        await up_writer.drain()
        # One request per connection: only the request judged above is forwarded. Anything the client
        # sends after it (a pipelined second request) is never read, let alone passed on.
        await pipe(up_reader, writer)
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
    try:
        images = load_allowed_images(catalogs, extra, strict=True)
    except ValueError as exc:
        sys.exit(f"docker policy: {exc}")   # never start with a catalog we could not read
    cfg = Config(mode, host, int(port or 2375), os.environ["DOCKER_POLICY_JOB_DIR"], images)
    server = await asyncio.start_server(lambda r, w: handle(r, w, cfg), "0.0.0.0", 2375, limit=1 << 16)
    log("started", mode=mode, upstream=f"{host}:{cfg.upstream_port}", job_dir=cfg.job_dir,
        images=len(cfg.images))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(serve())
