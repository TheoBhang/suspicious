import asyncio
import json
import os
import tempfile
import unittest

import docker_policy_proxy as dpp

JOBS = "/srv/cortex/jobs"
IMAGES = {"cortexneurons/virustotal_3_1:3.1", "mailheaderanalyzer:local"}


def create(**over):
    body = {
        "Image": "cortexneurons/virustotal_3_1:3.1",
        "Cmd": ["/worker/run"],
        "HostConfig": {"Binds": [f"{JOBS}/job1:/job"], "NetworkMode": "bridge"},
    }
    host = over.pop("HostConfig", None)
    body.update(over)
    if host is not None:
        body["HostConfig"] = {**body["HostConfig"], **host}
    return body


def check(body):
    return dpp.evaluate_create(body, IMAGES, JOBS)


class CreatePolicy(unittest.TestCase):
    def test_normal_analyzer_job_passes(self):
        self.assertEqual(check(create()), [])

    def test_read_only_bind_passes(self):
        self.assertEqual(check(create(HostConfig={"Binds": [f"{JOBS}/j:/job:ro"]})), [])

    def test_unlisted_image_is_denied(self):
        self.assertTrue(check(create(Image="alpine")))

    def test_untagged_image_means_latest(self):
        self.assertEqual(dpp.evaluate_create(create(Image="x/y"), {"x/y:latest"}, JOBS), [])

    def test_privileged_is_denied(self):
        self.assertTrue(check(create(HostConfig={"Privileged": True})))

    def test_host_root_bind_is_denied(self):
        self.assertTrue(check(create(HostConfig={"Binds": ["/:/host"]})))

    def test_bind_outside_job_dir_is_denied(self):
        self.assertTrue(check(create(HostConfig={"Binds": ["/etc:/x"]})))

    def test_sibling_directory_with_the_same_prefix_is_denied(self):
        self.assertTrue(check(create(HostConfig={"Binds": [f"{JOBS}-evil/x:/job"]})))

    def test_dot_dot_escape_is_denied(self):
        self.assertTrue(check(create(HostConfig={"Binds": [f"{JOBS}/../../etc:/x"]})))

    def test_named_volume_is_denied(self):
        self.assertTrue(check(create(HostConfig={"Binds": ["myvol:/x"]})))

    def test_mounts_are_denied(self):
        mount = {"Type": "bind", "Source": "/", "Target": "/h"}
        self.assertTrue(check(create(HostConfig={"Mounts": [mount]})))

    def test_each_dangerous_hostconfig_field_is_denied(self):
        for field, value in [
            ("CapAdd", ["SYS_ADMIN"]), ("Devices", [{"PathOnHost": "/dev/sda"}]),
            ("DeviceRequests", [{"Count": -1}]), ("PidMode", "host"), ("IpcMode", "host"),
            ("UsernsMode", "host"), ("UTSMode", "host"), ("NetworkMode", "host"),
            ("NetworkMode", "container:abc"), ("SecurityOpt", ["seccomp=unconfined"]),
            ("SecurityOpt", ["label=disable"]), ("VolumesFrom", ["other"]),
            ("CgroupParent", "/x"), ("Sysctls", {"a": "b"}), ("PortBindings", {"80/tcp": []}),
            ("Runtime", "kata"),
        ]:
            with self.subTest(field=field, value=value):
                self.assertTrue(check(create(HostConfig={field: value})))

    def test_harmless_hostconfig_fields_pass(self):
        host = {"AutoRemove": False, "Memory": 1 << 30, "NetworkMode": "default", "CapDrop": ["ALL"]}
        self.assertEqual(check(create(HostConfig=host)), [])

    def test_missing_hostconfig_passes(self):
        self.assertEqual(check({"Image": "mailheaderanalyzer:local"}), [])

    def test_non_object_body_is_denied(self):
        self.assertTrue(check([]))


class RequestPolicy(unittest.TestCase):
    def ev(self, method, path, query="", body=None):
        return dpp.evaluate_request(method, path, query, body, IMAGES, JOBS)

    def test_the_calls_cortex_makes_are_allowed(self):
        cid = "a" * 64
        for method, path in [
            ("GET", "/_ping"), ("GET", "/info"), ("GET", "/version"), ("GET", "/images/json"),
            ("GET", f"/containers/{cid}/json"), ("POST", f"/containers/{cid}/start"),
            ("POST", f"/containers/{cid}/wait"), ("GET", f"/containers/{cid}/logs"),
            ("DELETE", f"/containers/{cid}"), ("POST", f"/containers/{cid}/stop"),
            ("POST", f"/containers/{cid}/kill"),
        ]:
            with self.subTest(path=path):
                self.assertEqual(self.ev(method, path), [])
                self.assertEqual(self.ev(method, "/v1.43" + path), [])

    def test_create_is_judged_on_its_body(self):
        self.assertEqual(self.ev("POST", "/containers/create", "name=x", create()), [])
        self.assertTrue(self.ev("POST", "/v1.43/containers/create", "", create(Image="alpine")))

    def test_endpoints_cortex_never_needs_are_denied(self):
        cid = "b" * 64
        for method, path in [
            ("POST", f"/containers/{cid}/update"), ("POST", f"/containers/{cid}/rename"),
            ("PUT", f"/containers/{cid}/archive"), ("POST", f"/containers/{cid}/exec"),
            ("POST", "/containers/prune"), ("GET", "/volumes"), ("POST", "/build"),
            ("POST", "/networks/create"), ("GET", "/containers/json"),
        ]:
            with self.subTest(path=path):
                self.assertTrue(self.ev(method, path))

    def test_pull_only_of_listed_images(self):
        ok = "fromImage=cortexneurons%2Fvirustotal_3_1&tag=3.1"
        self.assertEqual(self.ev("POST", "/images/create", ok), [])
        self.assertTrue(self.ev("POST", "/images/create", "fromImage=evil%2Fx&tag=1"))
        self.assertTrue(self.ev("POST", "/images/create", "fromSrc=http%3A%2F%2Fx"))

    def test_path_tricks_are_not_allowed(self):
        self.assertTrue(self.ev("POST", "/containers/../containers/create/../x"))


class Catalog(unittest.TestCase):
    def test_reads_docker_images_from_list_and_dict_catalogs(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = os.path.join(d, "a.json"), os.path.join(d, "b.json")
            with open(a, "w") as fh:
                json.dump([{"dockerImage": "x/one:1"}, {"name": "no image"}], fh)
            with open(b, "w") as fh:
                json.dump({"analyzers": [{"dockerImage": "y/two"}]}, fh)
            got = dpp.load_allowed_images([a, b, os.path.join(d, "missing.json")], extra=["z/three:9"])
        self.assertEqual(got, {"x/one:1", "y/two:latest", "z/three:9"})


class Server(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.seen = []

        async def upstream(reader, writer):
            head = await reader.readuntil(b"\r\n\r\n")
            length = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":")[1])
            body = await reader.readexactly(length) if length else b""
            self.seen.append((head, body))
            writer.write(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
            writer.close()

        self.up = await asyncio.start_server(upstream, "127.0.0.1", 0)
        self.up_port = self.up.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.up.close()
        await self.up.wait_closed()

    async def request(self, mode, raw):
        cfg = dpp.Config(mode=mode, upstream_host="127.0.0.1", upstream_port=self.up_port,
                         job_dir=JOBS, images=IMAGES)
        srv = await asyncio.start_server(lambda r, w: dpp.handle(r, w, cfg), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(raw)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), 5)
        writer.close()
        srv.close()
        await srv.wait_closed()
        return data

    @staticmethod
    def post(body, chunked=False):
        data = json.dumps(body).encode()
        if chunked:
            half = len(data) // 2
            payload = b"%x\r\n%s\r\n%x\r\n%s\r\n0\r\n\r\n" % (half, data[:half], len(data) - half, data[half:])
            head = b"POST /v1.43/containers/create?name=x HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n"
            return head + payload
        head = b"POST /v1.43/containers/create?name=x HTTP/1.1\r\nHost: d\r\nContent-Length: %d\r\n\r\n" % len(data)
        return head + data

    async def test_good_create_is_forwarded_in_both_modes(self):
        for mode in ("log", "enforce"):
            out = await self.request(mode, self.post(create()))
            self.assertTrue(out.startswith(b"HTTP/1.1 201"), out)
        self.assertEqual(len(self.seen), 2)

    async def test_bad_create_is_forwarded_in_log_mode(self):
        out = await self.request("log", self.post(create(HostConfig={"Privileged": True})))
        self.assertTrue(out.startswith(b"HTTP/1.1 201"), out)
        self.assertEqual(len(self.seen), 1)

    async def test_bad_create_is_refused_in_enforce_mode(self):
        out = await self.request("enforce", self.post(create(HostConfig={"Privileged": True})))
        self.assertTrue(out.startswith(b"HTTP/1.1 403"), out)
        self.assertIn(b"Privileged", out)
        self.assertEqual(self.seen, [])

    async def test_chunked_body_is_judged_and_forwarded_whole(self):
        good = await self.request("enforce", self.post(create(), chunked=True))
        self.assertTrue(good.startswith(b"HTTP/1.1 201"), good)
        head, body = self.seen[0]
        self.assertEqual(json.loads(body), create())
        self.assertNotIn(b"chunked", head.lower())
        bad = await self.request("enforce", self.post(create(Image="alpine"), chunked=True))
        self.assertTrue(bad.startswith(b"HTTP/1.1 403"), bad)

    async def test_unparseable_create_body_is_refused_in_enforce_mode(self):
        raw = b"POST /containers/create HTTP/1.1\r\nHost: d\r\nContent-Length: 3\r\n\r\n{{{"
        out = await self.request("enforce", raw)
        self.assertTrue(out.startswith(b"HTTP/1.1 403"), out)

    async def test_unlisted_endpoint_is_refused_only_in_enforce_mode(self):
        raw = b"GET /volumes HTTP/1.1\r\nHost: d\r\n\r\n"
        self.assertTrue((await self.request("enforce", raw)).startswith(b"HTTP/1.1 403"))
        self.assertTrue((await self.request("log", raw)).startswith(b"HTTP/1.1 201"))

    async def test_upstream_is_asked_to_close_the_connection(self):
        await self.request("log", b"GET /_ping HTTP/1.1\r\nHost: d\r\nConnection: keep-alive\r\n\r\n")
        self.assertIn(b"connection: close", self.seen[0][0].lower())
        self.assertNotIn(b"keep-alive", self.seen[0][0].lower())


if __name__ == "__main__":
    unittest.main()
