import asyncio
import json
import os
import tempfile
import unittest
from unittest.mock import patch

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

    def test_only_the_default_networks_are_allowed(self):
        for ok in ("", "default", "bridge", "none"):
            with self.subTest(ok=ok):
                self.assertEqual(check(create(HostConfig={"NetworkMode": ok})), [])
        for bad in ("docker_cortex", "suspicious_net", "myproj_data", "host", "container:abc"):
            with self.subTest(bad=bad):
                self.assertTrue(check(create(HostConfig={"NetworkMode": bad})))

    def test_the_job_directory_itself_cannot_be_bound(self):
        self.assertTrue(check(create(HostConfig={"Binds": [f"{JOBS}:/job"]})))
        self.assertTrue(check(create(HostConfig={"Binds": [f"{JOBS}/:/job"]})))

    def test_key_case_does_not_hide_a_field(self):
        body = {"Image": "mailheaderanalyzer:local", "hostconfig": {"privileged": True, "binds": ["/:/h"]}}
        self.assertTrue(check(body))
        self.assertTrue(check({"image": "alpine"}))

    def test_a_repeated_key_in_any_case_is_refused_when_parsing(self):
        for raw in ('{"Image":"a","image":"b"}', '{"Image":"a","HostConfig":{"Privileged":false,"privileged":true}}',
                    '{"Image":"a","Image":"b"}'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    dpp.parse_json(raw.encode())
        self.assertEqual(dpp.parse_json(b'{"Image":"a","HostConfig":{"Binds":[]}}')["Image"], "a")

    def test_non_ascii_keys_are_refused_because_go_folds_them_onto_ascii(self):
        for raw in ('{"Image":"a","Ho\\u017ftConfig":{"Privileged":true}}', '{"\\u212aey":1}'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    dpp.parse_json(raw.encode())

    def test_networkingconfig_endpoints_are_refused(self):
        body = create()
        body["NetworkingConfig"] = {"EndpointsConfig": {"stack_data": {}}}
        self.assertTrue(check(body))
        body["NetworkingConfig"] = {"EndpointsConfig": {}}
        self.assertEqual(check(body), [])

    def test_hostconfig_fields_outside_the_allow_list_are_refused(self):
        for field, value in [("Tmpfs", {"/x": ""}), ("Links", ["a:b"]), ("CgroupnsMode", "host"),
                             ("StorageOpt", {"size": "1g"}), ("ExtraHosts", ["a:1.1.1.1"]),
                             ("OomKillDisable", True)]:
            with self.subTest(field=field):
                self.assertTrue(check(create(HostConfig={field: value})))

    def test_unmasking_paths_is_refused_even_when_empty(self):
        for field in ("MaskedPaths", "ReadonlyPaths"):
            with self.subTest(field=field):
                self.assertTrue(check(create(HostConfig={field: []})))
                self.assertEqual(check(create(HostConfig={field: None})), [])

    def test_resource_limits_and_autoremove_are_allowed(self):
        host = {"AutoRemove": True, "Memory": 1 << 30, "NanoCpus": 10**9, "CapDrop": ["ALL"],
                "PidsLimit": 100, "ReadonlyRootfs": True}
        self.assertEqual(check(create(HostConfig=host)), [])

    def test_a_symlink_in_the_job_directory_cannot_escape_it(self):
        with tempfile.TemporaryDirectory() as root:
            jobs = os.path.join(root, "jobs")
            os.makedirs(os.path.join(jobs, "real"))
            os.symlink("/etc", os.path.join(jobs, "link"))
            ok = dpp.evaluate_create(create(HostConfig={"Binds": [f"{jobs}/real:/job"]}), IMAGES, jobs)
            bad = dpp.evaluate_create(create(HostConfig={"Binds": [f"{jobs}/link:/job"]}), IMAGES, jobs)
        self.assertEqual(ok, [])
        self.assertTrue(bad)

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

    def test_a_tag_that_disagrees_with_the_tagged_name_is_refused(self):
        self.assertTrue(self.ev("POST", "/images/create",
                                "fromImage=cortexneurons%2Fvirustotal_3_1%3A3.1&tag=evil"))
        self.assertEqual(self.ev("POST", "/images/create",
                                 "fromImage=cortexneurons%2Fvirustotal_3_1%3A3.1&tag=3.1"), [])
        self.assertTrue(self.ev("POST", "/images/create", "fromImage=x%40sha256%3Aab&tag=1"))

    def test_a_body_is_refused_on_every_endpoint_but_create(self):
        ok = "fromImage=cortexneurons%2Fvirustotal_3_1&tag=3.1"
        self.assertEqual(dpp.evaluate_request("POST", "/images/create", ok, None, IMAGES, JOBS, raw_body=b""), [])
        self.assertTrue(dpp.evaluate_request("POST", "/images/create", ok, None, IMAGES, JOBS,
                                             raw_body=b"fromSrc=http%3A%2F%2Fevil"))
        self.assertTrue(dpp.evaluate_request("POST", "/containers/abc/start", "", None, IMAGES, JOBS,
                                             raw_body=b"{}"))

    def test_a_form_encoded_create_is_refused(self):
        self.assertTrue(dpp.evaluate_request("POST", "/containers/create", "", create(), IMAGES, JOBS,
                                             raw_body=b"{}", content_type="application/x-www-form-urlencoded"))
        self.assertEqual(dpp.evaluate_request("POST", "/containers/create", "", create(), IMAGES, JOBS,
                                              raw_body=b"{}", content_type="application/json"), [])

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


    def test_strict_mode_refuses_a_missing_or_empty_catalog(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                dpp.load_allowed_images([os.path.join(d, "missing.json")], strict=True)
            with self.assertRaises(ValueError):          # a directory where the file should be
                dpp.load_allowed_images([d], strict=True)
            empty = os.path.join(d, "e.json")
            with open(empty, "w") as fh:
                json.dump([], fh)
            with self.assertRaises(ValueError):
                dpp.load_allowed_images([empty], strict=True)


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
            first = head.split(b"\r\n")[0].decode()
            inspect = {"mine": (200, {"Config": {"Labels": {dpp.LABEL: "1"}}}),
                       "other": (200, {"Config": {"Labels": {}}}), "gone": (404, {"message": "no"})}
            for name, (code, doc) in inspect.items():
                if first.startswith(f"GET /containers/{name}/json"):
                    payload = json.dumps(doc).encode()
                    if first.endswith("HTTP/1.1"):   # the real daemon chunks HTTP/1.1 answers
                        writer.write(b"HTTP/1.1 %d X\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n%x\r\n%s\r\n0\r\n\r\n" % (code, len(payload), payload))
                    else:
                        writer.write(b"HTTP/1.0 %d X\r\nContent-Length: %d\r\n\r\n" % (code, len(payload)) + payload)
                    await writer.drain()
                    writer.close()
                    return
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
        sent = json.loads(body)
        self.assertEqual(sent.pop("Labels"), {dpp.LABEL: "1"})   # the analyzer label is the only change
        self.assertEqual(sent, create())
        self.assertNotIn(b"chunked", head.lower())
        bad = await self.request("enforce", self.post(create(Image="alpine"), chunked=True))
        self.assertTrue(bad.startswith(b"HTTP/1.1 403"), bad)

    async def test_pipelined_second_request_is_not_forwarded(self):
        first = b"GET /_ping HTTP/1.1\r\nHost: d\r\n\r\n"
        second = self.post(create(HostConfig={"Privileged": True}))
        await self.request("enforce", first + second)
        self.assertEqual(len(self.seen), 1)
        self.assertNotIn(b"containers/create", b"".join(h for h, _ in self.seen))

    async def test_upgrade_requests_are_refused(self):
        raw = b"POST /containers/abc/attach HTTP/1.1\r\nHost: d\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"
        out = await self.request("enforce", raw)
        self.assertTrue(out.startswith(b"HTTP/1.1 4"), out)
        self.assertEqual(self.seen, [])

    async def test_oversized_or_blank_chunk_sizes_are_refused(self):
        head = b"POST /containers/create HTTP/1.1\r\nHost: d\r\nTransfer-Encoding: chunked\r\n\r\n"
        for body in (b"FFFFFFFFF\r\n", b"\r\n0\r\n\r\n", b"zz\r\n"):
            with self.subTest(body=body):
                out = await self.request("log", head + body)
                self.assertTrue(out.startswith(b"HTTP/1.1 400"), out)
        self.assertEqual(self.seen, [])

    async def test_duplicate_key_create_body_is_refused_in_enforce_mode(self):
        raw = b'{"Image":"mailheaderanalyzer:local","HostConfig":{"Privileged":false,"privileged":true}}'
        head = b"POST /containers/create HTTP/1.1\r\nHost: d\r\nContent-Length: %d\r\n\r\n" % len(raw)
        out = await self.request("enforce", head + raw)
        self.assertTrue(out.startswith(b"HTTP/1.1 403"), out)

    async def test_an_allowed_create_gets_the_analyzer_label(self):
        await self.request("log", self.post(create(Labels={"a": "b"})))
        sent = json.loads(self.seen[0][1])
        self.assertEqual(sent["Labels"], {"a": "b", dpp.LABEL: "1"})
        self.assertEqual(sent["Image"], create()["Image"])

    async def test_a_lower_case_labels_key_is_replaced_not_duplicated(self):
        body = create()
        body["labels"] = {"x": "y"}
        await self.request("log", self.post(body))
        sent = json.loads(self.seen[0][1])
        self.assertNotIn("labels", sent)
        self.assertEqual(sent["Labels"], {"x": "y", dpp.LABEL: "1"})

    async def test_container_endpoints_only_reach_labelled_containers(self):
        def call(cid, method="POST", tail="start"):
            return f"{method} /containers/{cid}/{tail} HTTP/1.1\r\nHost: d\r\n\r\n".encode()
        out = await self.request("enforce", call("other"))
        self.assertTrue(out.startswith(b"HTTP/1.1 403"), out)
        self.assertEqual([h.split(b"\r\n")[0] for h, _ in self.seen],
                         [b"GET /containers/other/json HTTP/1.0"])            # only the inspect was sent
        self.seen.clear()
        out = await self.request("enforce", call("mine"))
        self.assertTrue(out.startswith(b"HTTP/1.1 201"), out)
        self.assertEqual(len(self.seen), 2)                                   # inspect, then the start
        self.seen.clear()
        out = await self.request("enforce", call("gone"))                     # nothing to protect
        self.assertTrue(out.startswith(b"HTTP/1.1 201"), out)

    async def test_container_endpoints_are_only_logged_in_log_mode(self):
        out = await self.request("log", b"DELETE /containers/other HTTP/1.1\r\nHost: d\r\n\r\n")
        self.assertTrue(out.startswith(b"HTTP/1.1 201"), out)

    async def test_a_stalled_request_is_cut_off(self):
        with patch.object(dpp, "READ_TIMEOUT", 0.3):
            cfg = dpp.Config(mode="enforce", upstream_host="127.0.0.1", upstream_port=self.up_port,
                             job_dir=JOBS, images=IMAGES)
            srv = await asyncio.start_server(lambda r, w: dpp.handle(r, w, cfg), "127.0.0.1", 0)
            reader, writer = await asyncio.open_connection("127.0.0.1", srv.sockets[0].getsockname()[1])
            writer.write(b"GET /_ping HTTP/1.1\r\nHost: d\r\n")     # never finishes the head
            await writer.drain()
            data = await asyncio.wait_for(reader.read(), 3)
            writer.close()
            srv.close()
            await srv.wait_closed()
        self.assertTrue(data == b"" or data.startswith(b"HTTP/1.1 400"), data)
        self.assertEqual(self.seen, [])

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
