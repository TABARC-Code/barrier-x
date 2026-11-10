# Copyright (C) 2026 barrier-x contributors. GPL; see ../../LICENSE.
import asyncio
import base64
import hashlib
import importlib.util
from pathlib import Path
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import sys
import zipfile
import json
import unittest

spec = importlib.util.spec_from_file_location("bridge", Path(__file__).with_name("bridge.py"))
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def address():
    key = bytes(range(32))
    suffix = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + key + suffix).digest()[:2]
    return base64.b32encode(key + checksum + suffix).decode().lower() + ".onion"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ValidationTests(unittest.TestCase):
    def test_only_checksummed_v3_onions(self):
        self.assertEqual(address(), bridge.onion_address(address().upper()))
        for bad in ("localhost", "127.0.0.1", "x.onion", "a" * 56 + ".onion",
                    address() + ".example", " " + address(), address() + "\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                bridge.onion_address(bad)

    def test_limits_and_path_injection(self):
        for value in (0, -1, 65536):
            with self.assertRaises(ValueError):
                bridge.port(value)
        for value in ("relative", "/tmp/x\nSocksPort 0", "/tmp/x\0"):
            with self.assertRaises(ValueError):
                bridge.quote_path(value)
        self.assertEqual('"/tmp/a \\"b"', bridge.quote_path('/tmp/a "b'))
        for value in (0, -1, float("nan"), float("inf"), 86401):
            with self.assertRaises(ValueError):
                bridge.Bridge(address(), idle_timeout=value)
        with self.assertRaises(ValueError):
            bridge.Bridge(address(), max_connections=5)
        with self.assertRaises(ValueError):
            bridge.Bridge(address(), socks_port=24801)

    def test_public_key_encoding(self):
        key = base64.b32encode(bytes(range(32))).decode().rstrip("=")
        self.assertEqual(key, bridge.public_key(key))
        for bad in ("A" * 52, key.lower(), key + "=", key[:-1] + "B", "x\n"):
            with self.assertRaises(ValueError):
                bridge.public_key(bad)

    @unittest.skipUnless(os.name == "posix", "POSIX service provisioning")
    def test_private_preset_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            root = str(Path(root).resolve())
            target = Path(root) / "new service"
            key = base64.b32encode(bytes(range(32))).decode().rstrip("=")
            bridge.provision_service(str(target), key, 24800, 24800)
            self.assertEqual(0o700, target.stat().st_mode & 0o777)
            self.assertEqual(0o600, (target / "torrc").stat().st_mode & 0o777)
            self.assertEqual("descriptor:x25519:" + key + "\n",
                             (target / "onion/authorized_clients/controller.auth").read_text())
            self.assertIn("HiddenServicePort 24800 127.0.0.1:24800\n", (target / "torrc").read_text())
            original = (target / "torrc").read_bytes()
            with self.assertRaises(FileExistsError):
                bridge.provision_service(str(target), key, 24801, 24800)
            self.assertEqual(original, (target / "torrc").read_bytes())

    @unittest.skipUnless(os.name == "posix", "POSIX service provisioning")
    def test_unsafe_and_linked_ancestors(self):
        with tempfile.TemporaryDirectory() as root:
            key = base64.b32encode(bytes(range(32))).decode().rstrip("=")
            root = str(Path(root).resolve())
            outer = Path(root) / "outer"
            outer.mkdir(mode=0o700)
            outer.chmod(0o777)
            try:
                with self.assertRaises(ValueError):
                    bridge.provision_service(str(outer / "new"), key, 24800, 24800)
                self.assertFalse((outer / "new").exists())
            finally:
                outer.chmod(0o700)
            link = Path(root) / "link"
            link.symlink_to(outer, target_is_directory=True)
            with self.assertRaises(OSError):
                bridge.provision_service(str(link / "new"), key, 24800, 24800)
            self.assertFalse((outer / "new").exists())


class PackagingTests(unittest.TestCase):
    def test_package_inputs_entrypoint_and_no_overwrite(self):
        build_spec = importlib.util.spec_from_file_location("build_plugin", Path(__file__).with_name("build_plugin.py"))
        builder = importlib.util.module_from_spec(build_spec)
        build_spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "plugin.pyz"
            builder.build(output)
            original = output.read_bytes()
            with self.assertRaises(FileExistsError):
                builder.build(output)
            self.assertEqual(original, output.read_bytes())
            with zipfile.ZipFile(output) as archive:
                self.assertEqual({"bridge.py", "plugin.json", "README.md", "LICENSE", "__main__.py"},
                                 set(archive.namelist()))
                self.assertIsNone(archive.testzip())
                self.assertEqual(Path(__file__).with_name("bridge.py").read_bytes(), archive.read("bridge.py"))
                self.assertEqual(bridge.VERSION, json.loads(archive.read("plugin.json"))["version"])
            run = subprocess.run([sys.executable, str(output), "--version"], check=True,
                                 capture_output=True, text=True, timeout=5)
            self.assertEqual(bridge.VERSION, run.stdout.strip())
            bad = subprocess.run([sys.executable, str(output), "connect", "--onion", "127.0.0.1"],
                                 capture_output=True, timeout=5)
            self.assertEqual(2, bad.returncode)


class NetworkTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servers = []
        self.tasks = set()
        self.bridges = []
        self.isolations = []
        self.requests = []
        self.closed = asyncio.Event()
        self.errors = []

    async def asyncTearDown(self):
        for item in self.bridges:
            await item.stop()
        for server in self.servers:
            server.close()
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for server in self.servers:
            await server.wait_closed()
        self.assertEqual([], self.errors)

    async def server(self, handler, **kwargs):
        async def run(reader, writer):
            try:
                await handler(reader, writer)
            except (OSError, asyncio.IncompleteReadError):
                pass
            finally:
                await bridge.close_stream(writer)
        def accept(reader, writer):
            task = asyncio.create_task(run(reader, writer))
            self.tasks.add(task)
            def finished(task):
                self.tasks.discard(task)
                if not task.cancelled() and task.exception() is not None:
                    self.errors.append(task.exception())
            task.add_done_callback(finished)
        server = await asyncio.start_server(accept, "127.0.0.1", 0, **kwargs)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def socks(self, reader, writer, reply=b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01", target=None):
        self.assertEqual(b"\x05\x01\x02", await reader.readexactly(3))
        writer.write(b"\x05")
        await writer.drain()
        await asyncio.sleep(0)
        writer.write(b"\x02")
        await writer.drain()
        version, size = await reader.readexactly(2)
        self.assertEqual(1, version)
        user = await reader.readexactly(size)
        size = (await reader.readexactly(1))[0]
        token = await reader.readexactly(size)
        self.assertEqual(b"<torS0X>0", user)
        self.isolations.append(token)
        writer.write(b"\x01\x00")
        await writer.drain()
        self.assertEqual(b"\x05\x01\x00\x03", await reader.readexactly(4))
        size = (await reader.readexactly(1))[0]
        self.requests.append((await reader.readexactly(size), await reader.readexactly(2)))
        for byte in reply:
            writer.write(bytes([byte]))
            await writer.drain()
            await asyncio.sleep(0)
        if target:
            remote = await asyncio.open_connection("127.0.0.1", target)
            try:
                await bridge.relay((reader, writer), remote, 5, 5, 1)
            finally:
                await bridge.close_stream(remote[1])
        else:
            while data := await reader.read(16384):
                writer.write(data)
                await writer.drain()
            writer.write(b"final")
            await writer.drain()
            self.closed.set()

    async def start_bridge(self, handler=None, **kwargs):
        socks_port = await self.server(handler or self.socks)
        item = bridge.Bridge(address(), socks_port=socks_port, listen_port=free_port(), **kwargs)
        await item.start()
        self.bridges.append(item)
        self.assertEqual("127.0.0.1", item.server.sockets[0].getsockname()[0])
        return item

    async def test_fragmented_socks_and_opaque_binary_half_close(self):
        item = await self.start_bridge()
        reader, writer = await asyncio.open_connection("127.0.0.1", item.listen_port)
        payload = bytes(range(256)) * 8192
        async def send():
            writer.write(payload)
            await writer.drain()
            writer.write_eof()
        sender = asyncio.create_task(send())
        response = await asyncio.wait_for(reader.readexactly(len(payload) + 5), 15)
        await sender
        self.assertEqual(payload + b"final", response)
        self.assertEqual((address().encode(), (24800).to_bytes(2, "big")), self.requests[0])
        self.assertEqual(b"", await asyncio.wait_for(reader.read(), 2))
        await bridge.close_stream(writer)

    async def test_invalid_socks_replies_and_no_direct_fallback(self):
        replies = (b"\x04\x00\x00\x01", b"\x05\x01\x00\x01", b"\x05\x00\x01\x01",
                   b"\x05\x00\x00\x09", b"\x05\x00\x00\x03\x00", b"\x05\x00")
        for reply in replies:
            with self.subTest(reply=reply):
                async def bad(reader, writer):
                    await self.socks(reader, writer, reply=reply)
                number = await self.server(bad)
                with self.assertRaises((bridge.ProtocolError, asyncio.IncompleteReadError, TimeoutError)):
                    await bridge.socks_connect(address(), 24800, number, 0.1)

    async def test_auth_downgrade_is_refused(self):
        async def bad(reader, writer):
            await reader.readexactly(3)
            writer.write(b"\x05\x00")
            await writer.drain()
            self.assertEqual(b"", await reader.read())
        number = await self.server(bad)
        with self.assertRaises(bridge.ProtocolError):
            await bridge.socks_connect(address(), 24800, number, 1)

    async def test_stalled_handshake_and_pending_shutdown(self):
        entered = asyncio.Event()
        async def stalled(reader, writer):
            await reader.readexactly(3)
            entered.set()
            await reader.read()
            self.closed.set()
        item = await self.start_bridge(stalled, connect_timeout=0.1)
        reader, writer = await asyncio.open_connection("127.0.0.1", item.listen_port)
        await asyncio.wait_for(entered.wait(), 1)
        self.assertEqual(b"", await asyncio.wait_for(reader.read(), 2))
        self.assertEqual(1, item.failures)
        await bridge.close_stream(writer)
        for _ in range(100):
            if not item.tasks:
                break
            await asyncio.sleep(0.01)
        self.assertFalse(item.tasks)
        entered.clear()
        item.connect_timeout = 30
        reader, writer = await asyncio.open_connection("127.0.0.1", item.listen_port)
        await asyncio.wait_for(entered.wait(), 1)
        await asyncio.wait_for(item.stop(), 3)
        self.assertEqual(b"", await asyncio.wait_for(reader.read(), 2))
        await bridge.close_stream(writer)
        self.assertFalse(item.tasks)

    async def test_limit_and_fresh_reconnect_isolation(self):
        item = await self.start_bridge()
        first_r, first_w = await asyncio.open_connection("127.0.0.1", item.listen_port)
        first_w.write(b"one")
        await first_w.drain()
        self.assertEqual(b"one", await asyncio.wait_for(first_r.readexactly(3), 2))
        second_r, second_w = await asyncio.open_connection("127.0.0.1", item.listen_port)
        try:
            self.assertEqual(b"", await asyncio.wait_for(second_r.read(), 2))
        except ConnectionResetError:
            pass
        await bridge.close_stream(second_w)
        first_w.write_eof()
        await asyncio.wait_for(first_r.read(), 2)
        await bridge.close_stream(first_w)
        for _ in range(100):
            if not item.tasks:
                break
            await asyncio.sleep(0.01)
        self.assertFalse(item.tasks)
        reader, writer = await asyncio.open_connection("127.0.0.1", item.listen_port)
        writer.write(b"two")
        await writer.drain()
        self.assertEqual(b"two", await asyncio.wait_for(reader.readexactly(3), 2))
        self.assertNotEqual(self.isolations[0], self.isolations[1])
        await bridge.close_stream(writer)

    async def test_idle_session_expires(self):
        async def quiet(reader, writer):
            await self.socks(reader, writer)
        item = await self.start_bridge(quiet, idle_timeout=0.1)
        reader, writer = await asyncio.open_connection("127.0.0.1", item.listen_port)
        self.assertEqual(b"", await asyncio.wait_for(reader.read(), 2))
        self.assertEqual(1, item.failures)
        await bridge.close_stream(writer)

    @unittest.skipUnless(os.name == "posix", "POSIX graceful process signal")
    async def test_packaged_cli_forwarding_and_shutdown(self):
        number = await self.server(self.socks)
        local_port = free_port()
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "plugin.pyz"
            subprocess.run([sys.executable, str(Path(__file__).with_name("build_plugin.py")),
                            "--output", str(output)], check=True, timeout=5)
            process = subprocess.Popen([sys.executable, str(output), "connect", "--onion", address(),
                                        "--socks-port", str(number), "--listen-port", str(local_port)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            writer = None
            try:
                line = await asyncio.wait_for(asyncio.to_thread(process.stdout.readline), 3)
                self.assertIn("Tor bridge listening on 127.0.0.1:", line)
                reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
                writer.write(b"archive session")
                await writer.drain()
                self.assertEqual(b"archive session", await asyncio.wait_for(reader.readexactly(15), 2))
                process.terminate()
                stdout, stderr = await asyncio.to_thread(process.communicate, timeout=5)
                self.assertEqual(0, process.returncode, stderr)
                self.assertIn("Tor bridge stopped", stdout)
                self.assertEqual(b"", await asyncio.wait_for(reader.read(), 2))
            finally:
                if writer is not None:
                    await bridge.close_stream(writer)
                if process.poll() is None:
                    process.kill()
                    await asyncio.to_thread(process.communicate, timeout=5)

    async def test_stalled_drain_is_bounded(self):
        class Reader:
            async def read(self, size):
                return bytes(size)
        class Writer:
            def __init__(self):
                self.transport = self
                self.data = bytearray()
            def set_write_buffer_limits(self, high, low):
                self.limits = (high, low)
            def write(self, data):
                self.data.extend(data)
            async def drain(self):
                await asyncio.Event().wait()
        writer = Writer()
        with self.assertRaises(TimeoutError):
            await bridge.pump(Reader(), writer, 1, 0.01)
        self.assertEqual(bridge.CHUNK, len(writer.data))
        self.assertEqual((bridge.CHUNK, bridge.CHUNK // 4), writer.limits)

    async def test_half_close_wait_is_bounded(self):
        async def silent(reader, writer):
            await reader.read()
            await asyncio.Event().wait()
        target = await self.server(silent)
        async def routed(reader, writer):
            await self.socks(reader, writer, target=target)
        item = await self.start_bridge(routed, half_close_timeout=0.05)
        reader, writer = await asyncio.open_connection("127.0.0.1", item.listen_port)
        writer.write_eof()
        self.assertEqual(b"", await asyncio.wait_for(reader.read(), 2))
        await bridge.close_stream(writer)
        self.assertEqual(1, item.failures)

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL command required for local TLS fixture")
    async def test_real_tls_crosses_bridge_and_untrusted_certificate_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            cert, key = Path(root) / "cert.pem", Path(root) / "key.pem"
            subprocess.run([shutil.which("openssl"), "req", "-x509", "-newkey", "rsa:3072", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost",
                            "-addext", "subjectAltName=DNS:localhost"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            async def echo(reader, writer):
                while data := await reader.read(16384):
                    writer.write(data)
                    await writer.drain()
            target = await self.server(echo, ssl=context)
            async def routed(reader, writer):
                await self.socks(reader, writer, target=target)
            item = await self.start_bridge(routed, max_connections=2)
            trusted = ssl.create_default_context(cafile=str(cert))
            reader, writer = await asyncio.open_connection("127.0.0.1", item.listen_port,
                                                           ssl=trusted, server_hostname="localhost")
            writer.write(b"encrypted input test")
            await writer.drain()
            self.assertEqual(b"encrypted input test", await asyncio.wait_for(reader.readexactly(20), 3))
            await bridge.close_stream(writer)
            loop = asyncio.get_running_loop()
            original_handler = loop.get_exception_handler()
            rejected = asyncio.Event()
            def expected_rejection(loop, context):
                if (context.get("message") == "Error on transport creation for incoming connection" and
                    isinstance(context.get("exception"), (ConnectionResetError, ssl.SSLError))):
                    rejected.set()
                else:
                    self.errors.append(context.get("exception") or RuntimeError("Unexpected loop error"))
            loop.set_exception_handler(expected_rejection)
            try:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    await asyncio.open_connection("127.0.0.1", item.listen_port,
                                                  ssl=ssl.create_default_context(), server_hostname="localhost")
                await asyncio.wait_for(rejected.wait(), 2)
            finally:
                loop.set_exception_handler(original_handler)


if __name__ == "__main__":
    unittest.main()
