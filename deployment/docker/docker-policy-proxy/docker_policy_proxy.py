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


VERSION = re.compile(r"^/v\d+(\.\d+)?(?=/|$)")
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
TARGET = re.compile(r"/[\x21-\x7e]*")
CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")   # tab is the only control character a header may hold


def strip_version(path):
    return VERSION.sub("", path)


def parse_head(head):
    """(request line, method, target, headers, names) of a request head, or ValueError. Strict on purpose:
    Go's HTTP parser and HAProxy accept looser framing than this (a bare LF, folded or repeated headers),
    and any difference between what is judged here and what the daemon reads would be a bypass."""
    lines = head[:-4].decode("latin-1").split("\r\n")
    if any(CONTROL.search(line) for line in lines):
        raise ValueError("control character in the request head")
    parts = lines[0].split(" ")
    if len(parts) != 3:
        raise ValueError("bad request line")
    method, target, version = parts
    if not (method.isalpha() and method.isupper() and TARGET.fullmatch(target)
            and version in ("HTTP/1.0", "HTTP/1.1")):
        raise ValueError("bad request line")
    headers, names = [], {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep or not TOKEN.fullmatch(name):
            raise ValueError(f"bad header line {line[:40]!r}")
        low = name.lower()
        if low in names:
            raise ValueError(f"header {name!r} is repeated")
        names[low] = value.strip()
        headers.append((name, value))
    return lines[0], method, target, headers, names


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
    # a link created inside the job directory must not point the bind somewhere else. strict=True: a
    # component the policy cannot inspect (a directory Cortex made unreadable, an SELinux label, a path
    # that does not exist) is refused. Non-strict realpath would take it for a plain directory.
    try:
        real, real_root = os.path.realpath(source, strict=True), os.path.realpath(root, strict=True)
    except (OSError, ValueError) as exc:   # ValueError: an embedded NUL or an unencodable character
        return f"bind source {source!r} cannot be resolved ({exc.__class__.__name__}): refused"
    if not real.startswith(real_root + "/"):
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
DANGEROUS_LOWER = frozenset(f.lower() for f in DANGEROUS_FIELDS)
# Top-level create fields with a value. docker-java sends all of them, null unless set (the dev run showed
# a non-null Image, Cmd, Env, HostConfig and Labels only); anything else with a value is refused.
ALLOWED_TOPLEVEL = {"image", "cmd", "entrypoint", "env", "user", "workingdir", "hostconfig", "labels",
                    "networkingconfig", "attachstdin", "attachstdout", "attachstderr", "tty", "openstdin",
                    "stdinonce", "hostname", "domainname", "argsescaped"}
ALLOWED_SECURITYOPT = {"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"}
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
    for key, value in body.items():
        if value not in EMPTY and key not in ALLOWED_TOPLEVEL:
            problems.append(f"{key} is not an allowed create field")
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
    options = host.get("securityopt") or []
    if not isinstance(options, list):
        problems.append("SecurityOpt is not a list")
        options = []
    for opt in options:
        if str(opt).lower() not in ALLOWED_SECURITYOPT:
            problems.append(f"SecurityOpt {opt!r} is refused (only no-new-privileges is allowed)")
    for field in UNMASKING:
        if host.get(field) is not None:
            problems.append(f"HostConfig.{field} is set")
    for field, value in host.items():
        if (value not in EMPTY and field not in ALLOWED_HOSTCONFIG and field not in JUDGED_ELSEWHERE
                and field not in DANGEROUS_LOWER):
            problems.append(f"HostConfig.{field} is not an allowed field")
    networking = body.get("networkingconfig")
    if isinstance(networking, dict) and networking.get("endpointsconfig") not in EMPTY:
        problems.append("NetworkingConfig.EndpointsConfig attaches networks: refused")
    binds = host.get("binds") or []
    if not isinstance(binds, list):
        problems.append("Binds is not a list")
        binds = []
    for bind in binds:
        problem = _bind_problem(bind, job_dir)
        if problem:
            problems.append(problem)
    return problems


def evaluate_request(method, path, query, body, images, job_dir, raw_body=b"", content_type=""):
    """Reasons a request is refused (empty list: allowed). `path` may carry /vX.YY."""
    path = strip_version(path)
    if ".." in path or "//" in path:
        return [f"path {path!r} is not normal"]
    if not any(method == m and re.fullmatch(p, path) for m, p in ENDPOINTS):
        return [f"{method} {path} is not an endpoint analyzer runs use"]
    is_create = method == "POST" and path == "/containers/create"
    if not is_create and raw_body:
        # The daemon merges a form-encoded POST body into the query, ahead of it: a body could change
        # what the checks below saw (for example fromImage).
        return [f"{method} {path} must not carry a body"]
    if is_create:
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
    keep["NonEmptyTopLevel"] = sorted(k for k, v in body.items() if v not in EMPTY)
    keep["EnvNames"] = sorted(e.split("=", 1)[0] for e in body.get("Env") or [] if isinstance(e, str))
    keep["HostConfig"] = body.get("HostConfig")
    return keep


def _stamp_of(paths):
    out = []
    for path in paths:
        try:
            st = os.stat(path)
            out.append((path, st.st_mtime_ns, st.st_ino))
        except OSError:
            out.append((path, None, None))
    return tuple(out)


@dataclasses.dataclass
class Config:
    mode: str
    upstream_host: str
    upstream_port: int
    job_dir: str
    images: set
    catalogs: tuple = ()
    extra: tuple = ()
    stamp: object = dataclasses.field(default=None, repr=False)
    ours: set = dataclasses.field(default_factory=set, repr=False)   # labelled containers (labels never change)

    def current_images(self):
        """The image set, re-read when a catalog file changed in place (mtime or inode). A refresh that
        cannot be read keeps the last good set. A file replaced by rename is still the old inode inside
        a single-file bind mount: recreate the service after replacing catalogs that way."""
        if not self.catalogs:
            return self.images
        stamp = _stamp_of(self.catalogs)
        if self.stamp is None:
            self.stamp = stamp
        elif stamp != self.stamp:
            self.stamp = stamp
            try:
                fresh = load_allowed_images(self.catalogs, self.extra, strict=True)
            except ValueError as exc:
                log("catalog_reload_failed", error=str(exc))
                return self.images
            self.images = fresh
            log("catalog_reloaded", images=len(fresh))
        return self.images


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


def container_id(method, path):
    """The container a request is about, or None (not a container call, or POST /containers/create:
    `create` is also a legal container name, so only that exact call is exempt)."""
    stripped = strip_version(path)
    if method == "POST" and stripped == "/containers/create":
        return None
    match = CONTAINER_PATH.fullmatch(stripped)
    return match.group(1) if match else None


async def _read_all(reader, limit):
    buf = b""
    while len(buf) < limit:
        chunk = await reader.read(65536)
        if not chunk:
            break
        buf += chunk
    return buf


async def ownership(cfg, cid):
    """"ours" (it carries our label), "absent" (no such container: nothing to protect) or "foreign". The
    label is read from the daemon through the upstream proxy, so it survives a restart of this service."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(cfg.upstream_host, cfg.upstream_port), READ_TIMEOUT)
        # HTTP/1.0: the daemon then answers with a Content-Length body and no chunked framing to decode,
        # and closes the connection, so reading to EOF gives the whole answer.
        writer.write(f"GET /containers/{cid}/json HTTP/1.0\r\nHost: docker\r\n\r\n".encode())
        await writer.drain()
        raw = await asyncio.wait_for(_read_all(reader, MAX_BODY), READ_TIMEOUT)
        head, _, body = raw.partition(b"\r\n\r\n")
        status = int(head.split(b" ", 2)[1])
        if status == 404:
            return "absent"
        if status != 200:
            return "foreign"
        labels = ((json.loads(body).get("Config") or {}).get("Labels")) or {}
        return "ours" if labels.get(LABEL) == "1" else "foreign"
    except (OSError, ValueError, IndexError, AttributeError, asyncio.TimeoutError):
        return "foreign"   # cannot tell: refuse
    finally:
        if writer is not None:
            writer.close()


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


async def watch_client(reader):
    try:
        while await reader.read(65536):
            pass
    except (ConnectionError, asyncio.CancelledError):
        pass


async def handle(reader, writer, cfg):
    up_writer = None
    try:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), READ_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            return await refuse(writer, 400, "request head not received")
        try:
            request_line, method, target, headers, names = parse_head(head)
        except ValueError as exc:
            return await refuse(writer, 400, str(exc))
        url = urllib.parse.urlsplit(target)
        if "upgrade" in names.get("connection", "").lower() or "upgrade" in names:
            log("request", method=method, path=url.path, verdict="deny", problems=["upgrade is refused"])
            return await refuse(writer, 403, "connection upgrades are refused")
        expect = names.get("expect", "").lower()
        if expect and expect != "100-continue":
            return await refuse(writer, 400, "unsupported Expect")
        if expect and (names.get("content-length") or "chunked" in names.get("transfer-encoding", "").lower()):
            writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")   # the body follows once the client hears this
            await writer.drain()
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
        if method == "POST" and strip_version(url.path) == "/containers/create":
            try:
                parsed = parse_json(body or b"null")
            except ValueError:
                parsed = None
        try:
            problems = evaluate_request(method, url.path, url.query, parsed, cfg.current_images(), cfg.job_dir,
                                        raw_body=body, content_type=names.get("content-type", ""))
        except Exception as exc:   # a body the checks cannot digest is refused, never a dropped connection
            problems = [f"policy error ({type(exc).__name__}): refused"]
        cid = container_id(method, url.path)
        if not problems and cid and cid not in cfg.ours:
            answer = await ownership(cfg, cid)
            if answer == "ours":
                if len(cfg.ours) > 4096:
                    cfg.ours.clear()
                cfg.ours.add(cid)
            elif answer == "foreign":
                problems = [f"container {cid!r} was not created through this policy"]
        verdict = "allow" if not problems else ("deny" if cfg.mode == "enforce" else "would_deny")
        fields = {"method": method, "path": url.path, "verdict": verdict, "problems": problems}
        if url.path.endswith("/containers/create"):
            fields["create"] = summarise_create(parsed)
        if not (verdict == "allow" and url.path.endswith("/_ping")):   # the healthcheck, every 10 s
            log("request", **fields)
        if verdict == "deny":
            return await refuse(writer, 403, "; ".join(problems))
        if method == "POST" and strip_version(url.path) == "/containers/create" and isinstance(parsed, dict):
            body = json.dumps(label_create(parsed)).encode()   # forwarded in log mode too, so containers
                                                                # made before enforce stay manageable

        skip = {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "content-length", "expect"}
        out = [request_line] + [f"{k}:{v}" for k, v in headers if k.lower() not in skip]
        out.append("Connection: close")
        if body:
            out.append(f"Content-Length: {len(body)}")
        up_reader, up_writer = await asyncio.open_connection(cfg.upstream_host, cfg.upstream_port)
        up_writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + body)
        await up_writer.drain()
        # One request per connection: only the request judged above is forwarded. Anything the client
        # sends after it (a pipelined second request) is read and thrown away, never passed on. When the
        # client goes away (Cortex drops a long wait or logs call) the upstream connection is closed too,
        # instead of staying open until the container exits. The only client is Cortex's docker-java,
        # which keeps the connection open while it waits and never half-closes.
        relay = asyncio.ensure_future(pipe(up_reader, writer))
        gone = asyncio.ensure_future(watch_client(reader))
        await asyncio.wait({relay, gone}, return_when=asyncio.FIRST_COMPLETED)
        for task in (relay, gone):
            task.cancel()
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
    cfg = Config(mode, host, int(port or 2375), os.environ["DOCKER_POLICY_JOB_DIR"], images,
                 catalogs=tuple(catalogs), extra=tuple(extra), stamp=_stamp_of(catalogs))
    server = await asyncio.start_server(lambda r, w: handle(r, w, cfg), "0.0.0.0", 2375, limit=1 << 16)
    log("started", mode=mode, upstream=f"{host}:{cfg.upstream_port}", job_dir=cfg.job_dir,
        images=len(cfg.images))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(serve())
