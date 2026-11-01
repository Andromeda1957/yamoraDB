"""Bounded opaque TCP multiplexing over an owner-started SSH stdio channel.

Run one endpoint in each managed worker. SSH and its strict host-key check
authenticate the transport; this helper neither reads keys nor terminates TLS.
Native peer authentication remains end to end. Stdout contains frames only.
"""

import argparse
import json
import os
import select
import socket
import struct
import sys
import threading
import time

HEADER = struct.Struct("!4sBII")
MAGIC = b"YS2M"
OPEN, DATA, CLOSE = 1, 2, 3
MAX_FRAME = 16384
MAX_CHANNELS = 32


class MuxError(RuntimeError):
    pass


class Mux:
    def __init__(self, reader, writer, targets, *, side, seconds=300, byte_limit=64 * 1024 * 1024):
        if side not in (0, 1) or not 0 < seconds <= 600 or not 0 < byte_limit <= 256 * 1024 * 1024:
            raise ValueError("invalid mux budget")
        self.reader, self.writer = reader, writer
        # Pipes can report writable with less than a full frame available.
        # Nonblocking descriptors keep a stalled SSH child within the deadline.
        os.set_blocking(reader, False)
        os.set_blocking(writer, False)
        self.targets = dict(targets)
        for name, port in self.targets.items():
            self.validate_endpoint(name, port)
        self.deadline = time.monotonic() + seconds
        self.byte_limit, self.bytes = byte_limit, 0
        self.next_channel = side + 1
        self.side = side
        self.channels, self.listeners, self.threads = {}, [], []
        self.lock = threading.RLock()
        self.write_lock = threading.Lock()
        self.stopped = threading.Event()
        self.failure = None

    @staticmethod
    def validate_endpoint(name, port):
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= 64
            or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in name)
            or type(port) is not int
            or not 1 <= port <= 65535
            or port == 8000
        ):
            raise ValueError("mux endpoints need a fixed name and non-owner loopback port")

    def transfer(self, fd, size=None, data=None):
        buffer = bytearray()
        while len(buffer) < size if size is not None else bool(data):
            remaining = self.deadline - time.monotonic()
            if self.stopped.is_set() or remaining <= 0:
                raise MuxError("mux deadline/stop")
            readable, writable, _ = select.select(
                [fd] if size is not None else [],
                [] if size is not None else [fd],
                [],
                min(0.2, remaining),
            )
            if size is not None and readable:
                try:
                    part = os.read(fd, size - len(buffer))
                except BlockingIOError:
                    continue
                if not part:
                    if not buffer:
                        return None
                    raise MuxError("truncated mux frame")
                buffer.extend(part)
            elif data is not None and writable:
                try:
                    count = os.write(fd, data)
                except BlockingIOError:
                    continue
                if count <= 0:
                    raise MuxError("mux write failed")
                data = data[count:]
        return bytes(buffer)

    def send(self, kind, channel, payload=b""):
        if len(payload) > MAX_FRAME or not 0 < channel <= 0xFFFFFFFF:
            raise MuxError("oversized/invalid outbound mux frame")
        with self.write_lock:
            if self.bytes + len(payload) > self.byte_limit:
                raise MuxError("mux byte budget exhausted")
            self.bytes += len(payload)
            self.transfer(
                self.writer, data=HEADER.pack(MAGIC, kind, channel, len(payload)) + payload
            )

    def spawn(self, function, *arguments):
        def bounded():
            try:
                function(*arguments)
            except (OSError, MuxError) as error:
                if not self.stopped.is_set():
                    self.failure = error
                    self.stopped.set()

        thread = threading.Thread(target=bounded)
        with self.lock:
            self.threads = [item for item in self.threads if item.is_alive()]
            self.threads.append(thread)
            thread.start()

    def close_channel(self, channel):
        with self.lock:
            connection = self.channels.pop(channel, None)
        if connection:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()

    def pump(self, channel, connection):
        try:
            while not self.stopped.is_set():
                try:
                    data = connection.recv(MAX_FRAME)
                except TimeoutError:
                    continue
                if not data:
                    break
                self.send(DATA, channel, data)
        except OSError:
            pass  # A peer/SSH disconnect makes its calls uncertain.
        finally:
            self.close_channel(channel)
            if not self.stopped.is_set():
                self.send(CLOSE, channel)

    def listen(self, name, port):
        self.validate_endpoint(name, port)
        listener = socket.socket()
        listener.bind(("127.0.0.1", port))
        listener.listen(MAX_CHANNELS)
        listener.settimeout(0.2)
        self.listeners.append(listener)

        def accept():
            while not self.stopped.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                connection.settimeout(0.2)
                with self.lock:
                    if len(self.channels) >= MAX_CHANNELS:
                        connection.close()
                        continue
                    channel = self.next_channel
                    self.next_channel += 2
                    if channel > 0xFFFFFFFF:
                        connection.close()
                        raise MuxError("mux channel budget exhausted")
                    self.channels[channel] = connection
                self.send(OPEN, channel, name.encode("ascii"))
                self.spawn(self.pump, channel, connection)

        self.spawn(accept)

    def serve(self):
        try:
            while not self.stopped.is_set():
                header = self.transfer(self.reader, size=HEADER.size)
                if header is None:
                    break
                magic, kind, channel, size = HEADER.unpack(header)
                if (
                    magic != MAGIC
                    or kind not in (OPEN, DATA, CLOSE)
                    or not channel
                    or size > MAX_FRAME
                ):
                    raise MuxError("invalid mux frame")
                payload = self.transfer(self.reader, size=size) if size else b""
                if payload is None:
                    raise MuxError("truncated mux payload")
                if kind == OPEN:
                    try:
                        name = payload.decode("ascii")
                    except UnicodeError as error:
                        raise MuxError("invalid mux endpoint") from error
                    if name not in self.targets or channel % 2 == (self.side + 1) % 2:
                        raise MuxError("unassigned mux endpoint/channel")
                    with self.lock:
                        if channel in self.channels or len(self.channels) >= MAX_CHANNELS:
                            raise MuxError("duplicate/excessive mux channel")
                    try:
                        connection = socket.create_connection(
                            ("127.0.0.1", self.targets[name]), timeout=2
                        )
                    except OSError:
                        self.send(CLOSE, channel)
                        continue
                    connection.settimeout(0.2)
                    with self.lock:
                        self.channels[channel] = connection
                    self.spawn(self.pump, channel, connection)
                elif kind == DATA:
                    with self.lock:
                        connection = self.channels.get(channel)
                    if connection:
                        try:
                            connection.settimeout(2)
                            connection.sendall(payload)
                            connection.settimeout(0.2)
                        except OSError:
                            self.close_channel(channel)
                elif payload:
                    raise MuxError("CLOSE frame has payload")
                else:
                    self.close_channel(channel)
            if self.failure:
                raise MuxError(str(self.failure))
        finally:
            self.close()

    def close(self):
        self.stopped.set()
        for listener in self.listeners:
            listener.close()
        with self.lock:
            channels = list(self.channels)
            threads = list(self.threads)
        for channel in channels:
            self.close_channel(channel)
        for thread in threads:
            if thread is not threading.current_thread():
                thread.join(timeout=3)
                if thread.is_alive():
                    raise MuxError("owned mux worker did not stop")


def endpoint(value):
    name, separator, port = value.partition("=")
    if not separator:
        raise argparse.ArgumentTypeError("expected name=port")
    try:
        port = int(port)
        Mux.validate_endpoint(name, port)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    return name, port


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--side", type=int, choices=(0, 1), required=True)
    parser.add_argument("--seconds", type=float, default=300)
    parser.add_argument("--target", type=endpoint, action="append", default=[])
    parser.add_argument("--listen", type=endpoint, action="append", default=[])
    args = parser.parse_args()
    if len(dict(args.target)) != len(args.target) or len(dict(args.listen)) != len(args.listen):
        parser.error("duplicate endpoint")
    mux = Mux(
        sys.stdin.fileno(),
        sys.stdout.fileno(),
        dict(args.target),
        side=args.side,
        seconds=args.seconds,
    )
    for name, port in args.listen:
        mux.listen(name, port)
    print(
        json.dumps({"event": "mux_ready", "listeners": dict(args.listen), "side": args.side}),
        file=sys.stderr,
        flush=True,
    )
    mux.serve()


if __name__ == "__main__":
    main()
