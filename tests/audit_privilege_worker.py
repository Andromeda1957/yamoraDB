"""Unprivileged roles for synthetic controls and native audit qualification.

Only the fixed container launcher sets up UIDs; roles verify dropped capability
and group state before protected-file, native IPC, TLS-daemon or cleanup work.
"""

import errno
import hashlib
import hmac
import json
import os
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
from pathlib import Path


def identity():
    fields = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    caps = {
        name: int(fields[name].strip(), 16) for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")
    }
    assert all(value == 0 for value in caps.values()), "CHILD_RETAINS_CAPABILITY"
    assert fields["NoNewPrivs"].strip() == "1", "CHILD_CAN_GAIN_PRIVILEGES"
    assert len(set(os.getresuid())) == 1 and len(set(os.getresgid())) == 1
    assert os.getgroups() == [], "CHILD_RETAINS_GROUPS"
    try:
        os.setresuid(0, 0, 0)
    except PermissionError:
        pass
    else:
        raise AssertionError("CHILD_CAN_REGAIN_LAUNCHER_UID")
    return {
        "pid": os.getpid(),
        "uid": list(os.getresuid()),
        "gid": list(os.getresgid()),
        "caps": caps,
        "no_new_privs": 1,
    }


def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def read_private(path, size):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size != size
        ):
            raise ValueError("invalid private fixture file")
        value = os.read(fd, size + 1)
        if len(value) != size:
            raise ValueError("incomplete private fixture file")
        return value
    finally:
        os.close(fd)


def publish(root, sequence):
    """Acknowledge only after file sync, atomic replacement and directory sync."""
    temporary = root / "anchor.next"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        value = sequence.to_bytes(8, "big")
        if os.write(fd, value) != len(value):
            raise OSError(errno.EIO, "short anchor publication")
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, root / "anchor")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def helper(root, address, control):
    evidence = identity()
    root = Path(root)
    if not root.exists():
        root.mkdir(mode=0o700)
        parent = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        fd = os.open(root / "key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            key = os.urandom(32)
            if os.write(fd, key) != 32:
                raise OSError(errno.EIO, "short private fixture key")
            os.fsync(fd)
        finally:
            os.close(fd)
        publish(root, 0)
    else:
        read_private(root / "key", 32)
    sequence = int.from_bytes(read_private(root / "anchor", 8), "big")
    if control == "readable-key":
        root.chmod(0o755)
        (root / "key").chmod(0o644)
    elif control == "replaceable-anchor":
        root.chmod(0o777)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as server:
        server.bind("\0" + address)
        server.listen(8)
        emit({"ready": evidence, "sequence": sequence})
        poisoned = False
        while True:
            ready, _, _ = select.select([server, sys.stdin], [], [], 10)
            if sys.stdin in ready:
                # EOF is the trusted launcher's lifecycle signal, not IPC auth.
                if not os.read(sys.stdin.fileno(), 1):
                    return
            if server not in ready:
                continue
            with server.accept()[0] as peer:
                peer.settimeout(2)
                _pid, uid, _gid = struct.unpack(
                    "3i",
                    peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")),
                )
                # Drain one bounded packet before closing, so a denial cannot
                # race an unread request into ECONNRESET at the client. No
                # application bytes are interpreted before peer authorization.
                data, _, flags, _ = peer.recvmsg(64)
                if uid != 1000 and control != "peer-uid-bypass":
                    peer.sendall(b"DENIED")
                    continue
                if flags & socket.MSG_TRUNC or data not in (b"READ", b"APPEND"):
                    peer.sendall(b"REFUSED")
                    continue
                if poisoned:
                    peer.sendall(b"UNCERTAIN")
                    continue
                try:
                    current = int.from_bytes(read_private(root / "anchor", 8), "big")
                    if current != sequence:
                        raise ValueError("anchor changed")
                    if data == b"APPEND":
                        publish(root, sequence + 1)
                        sequence += 1
                    peer.sendall(b"ACK:" + str(sequence).encode("ascii"))
                except (OSError, ValueError):
                    poisoned = True
                    peer.sendall(b"UNCERTAIN")


def exchange(address, command):
    evidence = identity()
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(3)
        client.connect("\0" + address)
        # Unauthorized peers may be rejected before receiving request bytes.
        try:
            client.sendall(command.encode("ascii"))
        except BrokenPipeError:
            pass
        reply = client.recv(64).decode("ascii")
    emit({"identity": evidence, "reply": reply})


def attacks(root, native=False):
    evidence = identity()
    root = Path(root)
    rollback = root.parent / "daemon-rollback"
    rollback.write_bytes(bytes(8))
    anchor = root / "anchors" / "anchor-v1.yda" if native else root / "anchor"
    actions = (
        ("key_read", lambda: (root / "key").read_bytes()),
        ("anchor_write", lambda: anchor.write_bytes(bytes(8))),
        ("anchor_replace", lambda: os.replace(rollback, anchor)),
        ("anchor_unlink", lambda: anchor.unlink()),
        ("key_write", lambda: (root / "key").write_bytes(bytes(32))),
        ("key_unlink", lambda: (root / "key").unlink()),
        ("anchor_chmod", lambda: anchor.chmod(0o666)),
        ("root_chmod", lambda: root.chmod(0o777)),
        ("root_replace", lambda: root.rename(root.parent / "displaced-helper")),
        ("case_chmod", lambda: root.parent.chmod(0o777)),
        ("case_replace", lambda: root.parent.rename(root.parent.with_name("displaced-case"))),
    )
    results = {}
    for name, action in actions:
        try:
            action()
        except OSError as error:
            results[name] = error.errno
        else:
            results[name] = 0
    emit({"identity": evidence, "attempts": results})


def main():
    mode = sys.argv[1]
    if mode == "helper":
        helper(*sys.argv[2:])
    elif mode == "exchange":
        exchange(*sys.argv[2:])
    elif mode == "attacks":
        attacks(*sys.argv[2:])
    elif mode == "native-attacks":
        attacks(sys.argv[2], native=True)
    elif mode == "prepare-native":
        evidence = identity()
        root = Path(sys.argv[2])
        root.mkdir(mode=0o700)
        for child in ("log", "anchors"):
            (root / child).mkdir(mode=0o700)
        fd = os.open(root / "key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            key = os.urandom(32)
            if os.write(fd, key) != 32:
                raise OSError(errno.EIO, "short native key")
            os.fsync(fd)
        finally:
            os.close(fd)
        public = root.parent / "public"
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        for path in (root / "log", root / "anchors", root, public, root.parent):
            directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        emit({"identity": evidence})
    elif mode == "prepare-daemon":
        evidence = identity()
        root = Path(sys.argv[2])
        root.mkdir(mode=0o700)
        (root / "data").mkdir(mode=0o700)
        for name, token in (("read", "r" * 64), ("write", "w" * 64)):
            fd = os.open(root / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(token)
        subprocess.run(
            [
                "/usr/bin/openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-keyout",
                str(root / "key.pem"),
                "-out",
                str(root / "cert.pem"),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        (root / "key.pem").chmod(0o600)
        emit({"identity": evidence, "certificate": (root / "cert.pem").read_text()})
    elif mode == "prepare-encrypted-daemon":
        evidence = identity()
        root = Path(sys.argv[2])
        data = root / "encrypted"
        data.mkdir(mode=0o700)
        config = {
            "version": 1,
            "mode": "create",
            "store_id": "a1" * 16,
            "object_id": "b2" * 32,
            "generation": 1,
            "maximum_bytes": 1024 * 1024,
            "cache_bytes": 32768,
            "key_id": "isolated-audit-fixture-key",
            "provider": {
                "type": "local",
                "keys": [{"id": "isolated-audit-fixture-key", "key_hex": "51" * 32}],
            },
        }
        fd = os.open(root / "encrypted.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(config, stream)
        emit({"identity": evidence})
    elif mode == "encrypted-state":
        evidence = identity()
        data = Path(sys.argv[2]) / "encrypted/.yamora-disk"
        wire = data.read_bytes()
        assert wire.startswith(b"YDENVP1\0")
        assert b"private-field-value" not in wire
        emit({"identity": evidence, "ciphertext": hashlib.sha256(wire).hexdigest()})
    elif mode == "poison-encrypted-publication":
        evidence = identity()
        path = Path(sys.argv[2]) / "encrypted/unexpected-publication-artifact"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        emit({"identity": evidence})
    elif mode == "native-directory":
        evidence = identity()
        Path(sys.argv[2]).mkdir(mode=0o700)
        emit({"identity": evidence})
    elif mode == "terminate-native":
        evidence = identity()
        try:
            os.kill(int(sys.argv[2]), signal.SIGTERM)
        except ProcessLookupError:
            pass
        emit({"identity": evidence})
    elif mode == "daemon-certificate":
        emit({"identity": identity(), "certificate": (Path(sys.argv[2]) / "cert.pem").read_text()})
    elif mode == "native-inspect":
        evidence = identity()
        root = Path(sys.argv[2])
        key = read_private(root / "key", 32)
        records, previous = [], bytes(32)
        # Further hex-encoded values a caller proved must never reach the log.
        forbidden = (b"r" * 64, b"w" * 64, b"private-field-value") + tuple(
            bytes.fromhex(value) for value in sys.argv[3:]
        )
        for path in sorted((root / "log").iterdir()):
            data = path.read_bytes()
            assert len(data) % 1024 == 0
            assert all(value not in data for value in forbidden), "AUDIT_SECRET_REDACTION"
            for at in range(0, len(data), 1024):
                frame = data[at : at + 1024]
                assert frame[:8] == b"YDAUDR01"
                assert hmac.compare_digest(
                    hmac.digest(key, b"YAMORA-AUDIT-RECORD-V1\0" + frame[:992], "sha256"),
                    frame[992:],
                ), "AUDIT_NATIVE_MAC"
                assert frame[96:128] == previous, "AUDIT_NATIVE_CHAIN"
                previous = frame[992:]
                records.append(
                    {
                        "kind": int.from_bytes(frame[12:16], "little"),
                        "sequence": int.from_bytes(frame[80:88], "little"),
                        "segment": int.from_bytes(frame[72:80], "little"),
                        "intent": int.from_bytes(frame[88:96], "little"),
                        "authentication": int.from_bytes(frame[148:152], "little"),
                        "operation": int.from_bytes(frame[152:156], "little"),
                        "actor": frame[168 : 168 + int.from_bytes(frame[164:168], "little")].decode(
                            "ascii"
                        ),
                        "subject": frame[
                            368 : 368 + int.from_bytes(frame[364:368], "little")
                        ].decode("ascii"),
                        "outcome": int.from_bytes(frame[156:160], "little"),
                        "status": int.from_bytes(frame[160:164], "little"),
                        "has_revision": bool(int.from_bytes(frame[20:24], "little")),
                        "revision": frame[296:312].decode("ascii"),
                    }
                )
        anchor = read_private(root / "anchors/anchor-v1.yda", 128)
        assert anchor[80:112] == previous, "AUDIT_NATIVE_EXACT_ANCHOR"
        emit({"identity": evidence, "records": records})
    elif mode == "job-gate-state":
        emit({"identity": identity(), "entered": Path(sys.argv[2]).is_file()})
    elif mode == "release-job-gate":
        evidence = identity()
        Path(sys.argv[2]).unlink(missing_ok=True)
        emit({"identity": evidence})
    elif mode in ("native-exec", "native-gated-exec"):
        emit({"identity": identity()})
        args = sys.argv[2:] if mode == "native-exec" else sys.argv[3:]
        os.execve(
            args[0],
            args,
            {
                **os.environ,
                **({"YAMORA_TEST_JOB_GATE": sys.argv[2]} if mode == "native-gated-exec" else {}),
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
            },
        )
    elif mode == "native-sequence":
        evidence = identity()
        value = read_private(Path(sys.argv[2]) / "anchors" / "anchor-v1.yda", 128)
        emit({"identity": evidence, "sequence": int.from_bytes(value[72:80], "little")})
    elif mode == "native-ipc":
        native_ipc(*sys.argv[2:])
    elif mode == "native-contaminate":
        evidence = identity()
        root = Path(sys.argv[2])
        with (root / "anchors" / "orphan.tmp").open("xb"):
            pass
        emit({"identity": evidence})
    elif mode == "silent-helper":
        evidence = identity()
        path = sys.argv[2]
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
            try:
                listener.bind(path)
                os.chmod(path, 0o666)
                listener.listen(1)
                listener.settimeout(5)
                emit({"identity": evidence})
                with listener.accept()[0] as peer:
                    peer.settimeout(5)
                    hello = peer.recv(512)
                    assert len(hello) == 512
                    payload = struct.pack("<II", 0, 1) + bytes([1]) * 16 + bytes(28)
                    reply = (
                        b"YDAUIP01" + struct.pack("<IIQII", 1, 4, 1, 52, 0) + payload + bytes(428)
                    )
                    peer.sendall(reply)
                    begin = peer.recv(512)
                    assert len(begin) == 512
                    emit({"waiting": True})
                    assert peer.recv(512) == b"", "DEADLINE_WAITER_SENT_A_SECOND_PACKET"
            finally:
                os.unlink(path)
    elif mode == "cleanup":
        identity()
        root = Path(sys.argv[2])
        # Only the exact synthetic allocation supplied by the fixture launcher.
        if root.exists():
            shutil.rmtree(root)
        emit({"cleaned": True})
    elif mode == "crash":
        evidence = identity()
        os.kill(int(sys.argv[2]), signal.SIGKILL)
        emit({"identity": evidence})
    else:
        raise ValueError("unknown fixture role")


def native_ipc(path, mode):
    evidence = identity()

    def packet(kind, request, payload=b""):
        return (
            b"YDAUIP01"
            + struct.pack("<IIQII", 1, kind, request, len(payload), 0)
            + payload
            + bytes(480 - len(payload))
        )

    def connect():
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        peer.settimeout(3)
        peer.connect(path)
        peer.sendall(packet(1, 1))
        reply = peer.recv(512)
        assert len(reply) == 512 and struct.unpack_from("<I", reply, 32)[0] == 0, (
            "HELLO_CONTROL_FAILED"
        )
        return peer

    with connect() as first:
        if mode in ("malformed", "truncated", "oversized"):
            bad = bytearray(
                packet(2, 2, struct.pack("<QIIII", 0, 1, 3, 3, 7) + b"fixture" + bytes(121))
            )
            if mode == "malformed":
                bad[511] = 1
            elif mode == "truncated":
                bad = bad[:-1]
            else:
                bad += bytes(1)
            first.sendall(bad)
            try:
                result = first.recv(512)
            except (ConnectionResetError, BrokenPipeError):
                result = b""
            assert result == b"", "MALFORMED_PACKET_WAS_ACCEPTED"
        elif mode in ("handles", "lost-begin", "lost-finish"):
            first.sendall(
                packet(2, 2, struct.pack("<QIIII", 0, 1, 3, 3, 7) + b"fixture" + bytes(121))
            )
            begun = first.recv(512)
            assert len(begun) == 512 and struct.unpack_from("<I", begun, 32)[0] == 0, (
                "BEGIN_CONTROL_FAILED"
            )
            handle = begun[56:72]
            finish = handle + struct.pack("<QQIII", 0, 0, 2, 200, 0) + bytes(16)
            if mode == "lost-begin":
                first.close()
            elif mode == "lost-finish":
                first.sendall(packet(3, 3, finish))
                first.close()
            else:
                with connect() as second:
                    for value in (bytes([42]) * 16, handle):
                        second.sendall(packet(3, 2 if value != handle else 3, value + finish[16:]))
                        reply = second.recv(512)
                        assert struct.unpack_from("<I", reply, 32)[0] == 1, (
                            "FOREIGN_OR_INVENTED_HANDLE_ACCEPTED"
                        )
                first.sendall(packet(3, 3, finish))
                assert struct.unpack_from("<I", first.recv(512), 32)[0] == 0, "OWN_HANDLE_REFUSED"
                first.sendall(packet(3, 4, finish))
                assert struct.unpack_from("<I", first.recv(512), 32)[0] == 1, (
                    "DUPLICATE_HANDLE_ACCEPTED"
                )
        else:
            raise ValueError("unknown native IPC case")
    emit({"identity": evidence, "verified": mode})


if __name__ == "__main__":
    main()
