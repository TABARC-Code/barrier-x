#!/usr/bin/env python3
# Copyright (C) 2026 barrier-x contributors. GPL; see ../../LICENSE.
"""Optional loopback transport for an existing Tor onion service. Python 3.11+."""
import argparse
import asyncio
import base64
import hashlib
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import sys

VERSION = "0.1.0"
CHUNK = 16384
STREAM_LIMIT = 65536


class ProtocolError(Exception):
    pass


def onion_address(value):
    value = value.lower()
    if not re.fullmatch(r"[a-z2-7]{56}\.onion", value):
        raise ValueError("A complete v3 onion address is required")
    raw = base64.b32decode(value[:-6].upper())
    check = hashlib.sha3_256(b".onion checksum" + raw[:32] + raw[-1:]).digest()[:2]
    if raw[-1] != 3 or raw[32:34] != check:
        raise ValueError("Invalid onion version or checksum")
    return value


def port(value):
    number = int(value)
    if not 1 <= number <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    return number


def public_key(value):
    if not re.fullmatch(r"[A-Z2-7]{52}", value):
        raise ValueError("A canonical base32 X25519 public key is required")
    raw = base64.b32decode(value + "====")
    if raw == bytes(32) or base64.b32encode(raw).decode().rstrip("=") != value:
        raise ValueError("Invalid X25519 public key encoding")
    return value


def quote_path(value):
    text = str(value)
    if not Path(text).is_absolute() or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValueError("An absolute path without control characters is required")
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"') + '"'


async def close_stream(writer):
    writer.close()
    try:
        async with asyncio.timeout(2):
            await writer.wait_closed()
    except (OSError, TimeoutError):
        writer.transport.abort()


async def socks_connect(onion, remote_port, socks_port, timeout):
    onion = onion_address(onion)
    port(remote_port)
    port(socks_port)
    writer = None
    try:
        async with asyncio.timeout(timeout):
            # I pass the onion name to Tor. Local DNS has no business seeing it.
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", socks_port, family=socket.AF_INET, limit=STREAM_LIMIT)
            writer.write(b"\x05\x01\x02")
            await writer.drain()
            if await reader.readexactly(2) != b"\x05\x02":
                raise ProtocolError("SOCKS_AUTH_METHOD")
            user = b"<torS0X>0"
            isolation = secrets.token_hex(16).encode("ascii")
            writer.write(b"\x01" + bytes([len(user)]) + user + bytes([len(isolation)]) + isolation)
            await writer.drain()
            if await reader.readexactly(2) != b"\x01\x00":
                raise ProtocolError("SOCKS_AUTH_REJECTED")
            host = onion.encode("ascii")
            writer.write(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + remote_port.to_bytes(2, "big"))
            await writer.drain()
            header = await reader.readexactly(4)
            if header[:3] != b"\x05\x00\x00":
                raise ProtocolError("SOCKS_CONNECT_REJECTED")
            if header[3] == 1:
                await reader.readexactly(6)
            elif header[3] == 4:
                await reader.readexactly(18)
            elif header[3] == 3:
                length = (await reader.readexactly(1))[0]
                if not length:
                    raise ProtocolError("SOCKS_EMPTY_ADDRESS")
                await reader.readexactly(length + 2)
            else:
                raise ProtocolError("SOCKS_ADDRESS_TYPE")
            return reader, writer
    except BaseException:
        if writer is not None:
            writer.close()
            # Cancellation must release the socket too; close() comes before any wait.
            await close_stream(writer)
        raise


async def pump(reader, writer, idle_timeout, write_timeout):
    writer.transport.set_write_buffer_limits(high=CHUNK, low=CHUNK // 4)
    while True:
        async with asyncio.timeout(idle_timeout):
            data = await reader.read(CHUNK)
        if not data:
            if writer.can_write_eof():
                writer.write_eof()
                async with asyncio.timeout(write_timeout):
                    await writer.drain()
            return
        writer.write(data)
        async with asyncio.timeout(write_timeout):
            await writer.drain()


async def relay(left, right, idle_timeout, write_timeout, half_close_timeout):
    tasks = [asyncio.create_task(pump(left[0], right[1], idle_timeout, write_timeout)),
             asyncio.create_task(pump(right[0], left[1], idle_timeout, write_timeout))]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        if pending:
            async with asyncio.timeout(half_close_timeout):
                await asyncio.gather(*pending)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class Bridge:
    def __init__(self, onion, remote_port=24800, socks_port=9050, listen_port=24801,
                 connect_timeout=30, idle_timeout=3600, write_timeout=30,
                 half_close_timeout=5, max_connections=1):
        self.onion = onion_address(onion)
        self.remote_port = port(remote_port)
        self.socks_port = port(socks_port)
        self.listen_port = port(listen_port)
        if self.listen_port == self.socks_port:
            raise ValueError("Bridge and SOCKS ports must differ")
        if not 1 <= max_connections <= 4:
            raise ValueError("Connection limit must be between 1 and 4")
        for value in (connect_timeout, idle_timeout, write_timeout, half_close_timeout):
            if not 0 < value <= 86400:
                raise ValueError("Timeout must be positive and at most one day")
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self.write_timeout = write_timeout
        self.half_close_timeout = half_close_timeout
        self.max_connections = max_connections
        self.tasks = set()
        self.server = None
        self.stopping = False
        self.failures = 0

    async def start(self):
        if self.server is not None or self.stopping:
            raise RuntimeError("Bridge cannot be started twice")
        self.server = await asyncio.start_server(
            self.accept, "127.0.0.1", self.listen_port, family=socket.AF_INET,
            limit=STREAM_LIMIT, backlog=4)

    def accept(self, reader, writer):
        if self.stopping or len(self.tasks) >= self.max_connections:
            writer.transport.abort()
            return
        task = asyncio.create_task(self.handle(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.finished)

    def finished(self, task):
        self.tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            self.failures += 1

    async def handle(self, reader, writer):
        remote = None
        try:
            remote = await socks_connect(self.onion, self.remote_port,
                                         self.socks_port, self.connect_timeout)
            await relay((reader, writer), remote, self.idle_timeout,
                        self.write_timeout, self.half_close_timeout)
        except (ProtocolError, OSError, TimeoutError, asyncio.IncompleteReadError):
            self.failures += 1
            # No payloads, onion names, Tor replies or unbounded per-failure logs.
        finally:
            writer.close()
            if remote is not None:
                remote[1].close()
            await asyncio.gather(close_stream(writer),
                                 *([close_stream(remote[1])] if remote else []))

    async def stop(self):
        self.stopping = True
        if self.server is not None:
            self.server.close()
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self.server is not None:
            await self.server.wait_closed()


def provision_service(directory, key, engine_port, onion_port):
    """Create a fresh private POSIX service preset. Tor remains a separate dependency."""
    public_key(key)
    port(engine_port)
    port(onion_port)
    path = Path(directory)
    quote_path(path)
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("Service provisioning needs POSIX directory handles; use the manual Windows setup")
    if len(path.parts) > 128 or ".." in path.parts or path.name in ("", ".", ".."):
        raise ValueError("Invalid service folder")
    held = []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open("/", flags)
        held.append(fd)
        for part in path.parts[1:-1]:
            info = os.fstat(fd)
            shared = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if info.st_uid not in (0, os.geteuid()) or (info.st_mode & 0o022 and not shared):
                raise ValueError("Unsafe service ancestor")
            fd = os.open(part, flags, dir_fd=fd)
            held.append(fd)
        info = os.fstat(fd)
        shared = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if info.st_uid not in (0, os.geteuid()) or (info.st_mode & 0o022 and not shared):
            raise ValueError("Unsafe service ancestor")
        os.mkdir(path.name, 0o700, dir_fd=fd)  # An existing profile is never overwritten.
        fd = os.open(path.name, flags, dir_fd=fd)
        held.append(fd)
        os.mkdir("onion", 0o700, dir_fd=fd)
        onion_fd = os.open("onion", flags, dir_fd=fd)
        held.append(onion_fd)
        os.mkdir("authorized_clients", 0o700, dir_fd=onion_fd)
        auth_fd = os.open("authorized_clients", flags, dir_fd=onion_fd)
        held.append(auth_fd)
        def write_at(parent, name, content):
            output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
            with os.fdopen(output, "w", encoding="utf-8", newline="\n") as file:
                file.write(content)
                file.flush()
                os.fsync(file.fileno())
        write_at(auth_fd, "controller.auth", "descriptor:x25519:" + key + "\n")
        config = ("SocksPort 0\nDataDirectory " + quote_path(path / "data") + "\n"
                  "HiddenServiceDir " + quote_path(path / "onion") + "\n"
                  "HiddenServiceVersion 3\nHiddenServicePort " + str(onion_port) +
                  " 127.0.0.1:" + str(engine_port) + "\n")
        # I write the launchable config last. An interrupted setup isn't a public service preset.
        write_at(fd, "torrc", config)
    finally:
        for fd in reversed(held):
            os.close(fd)


async def run_bridge(args):
    bridge = Bridge(args.onion, args.remote_port, args.socks_port, args.listen_port,
                    args.connect_timeout, args.idle_timeout, args.write_timeout,
                    args.half_close_timeout, args.max_connections)
    await bridge.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in ("SIGINT", "SIGTERM"):
        try:
            loop.add_signal_handler(getattr(signal, name), stop.set)
        except (NotImplementedError, RuntimeError):
            pass
    # FUTURE(BX-032): I need real Tor loss/held-key checks before adding a GUI switch.
    print("Tor bridge listening on 127.0.0.1:" + str(bridge.listen_port), flush=True)
    print("Keep Barrier encryption and peer approval enabled. Ctrl+C stops the bridge.", flush=True)
    try:
        await stop.wait()
    finally:
        await bridge.stop()
        print("Tor bridge stopped; failed or timed-out sessions: " + str(bridge.failures), flush=True)


def main(argv=None):
    if sys.version_info < (3, 11):
        raise SystemExit("Tor plugin requires Python 3.11 or newer")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    commands = parser.add_subparsers(dest="command", required=True)
    connect = commands.add_parser("connect", help="Bridge a local Barrier client through an existing Tor SOCKS listener")
    connect.add_argument("--onion", required=True, type=onion_address)
    for option, default in (("remote-port", 24800), ("socks-port", 9050), ("listen-port", 24801)):
        connect.add_argument("--" + option, type=port, default=default)
    for option, default in (("connect-timeout", 30), ("idle-timeout", 3600),
                            ("write-timeout", 30), ("half-close-timeout", 5)):
        connect.add_argument("--" + option, type=float, default=default)
    connect.add_argument("--max-connections", type=int, default=1)
    service = commands.add_parser("provision-service", help="Create a new authenticated POSIX Tor service preset")
    service.add_argument("--directory", required=True)
    service.add_argument("--client-public-key", required=True, type=public_key)
    service.add_argument("--engine-port", default=24800, type=port)
    service.add_argument("--onion-port", default=24800, type=port)
    args = parser.parse_args(argv)
    try:
        if args.command == "connect":
            asyncio.run(run_bridge(args))
        else:
            provision_service(args.directory, args.client_public_key, args.engine_port, args.onion_port)
            print("Private service preset created. Review it and run Tor as the same user.")
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError) as error:
        # Fixed categories keep filesystem paths and hostile exception text out of diagnostics.
        parser.exit(2, "Tor plugin stopped: " + type(error).__name__ + ". Check configuration and permissions.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
