"""One explicit SSH/Ed25519 file-key backend; no agent or implicit identity."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
import unicodedata
from contextlib import contextmanager

from .git_reader import plain_path
from .git_writer import GitInfrastructureError
from .model import PlanError
from .model import canonical
from .model import strict_json
from .validation import keys

MAX_COMMIT = 65536


def _text(value, maximum, *, ascii_only=False):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise PlanError("invalid bounded identity text")
    if any(unicodedata.category(c).startswith("C") for c in value):
        raise PlanError("control characters in identity")
    if value.strip() != value or (ascii_only and not value.isascii()):
        raise PlanError("invalid identity encoding or whitespace")
    return value


def policy(value):
    result = strict_json(canonical(value))
    keys(result, ("backend", "principal", "public_key", "fingerprint"))
    if result["backend"] != "ssh-ed25519-v1":
        raise PlanError("unsupported signing backend")
    principal = _text(result["principal"], 128, ascii_only=True)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@._+\-]{0,127}", principal) is None:
        raise PlanError("signing principal must be literal")
    public = _text(result["public_key"], 128, ascii_only=True)
    if not public.startswith("ssh-ed25519 ") or len(public.split(" ")) != 2:
        raise PlanError("expected one canonical Ed25519 public record")
    try:
        blob = base64.b64decode(public.split(" ")[1], validate=True)
    except (ValueError, TypeError) as exc:
        raise PlanError("invalid signing public key") from exc
    prefix = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
    if len(blob) != len(prefix) + 32 or not blob.startswith(prefix):
        raise PlanError("invalid Ed25519 public blob")
    if base64.b64encode(blob).decode("ascii") != public.split(" ")[1]:
        raise PlanError("noncanonical signing public key")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    if result["fingerprint"] != fingerprint:
        raise PlanError("signer fingerprint does not match public key")
    return result


def allowed_signers(value):
    value = policy(value)
    return value["principal"] + ' namespaces="git" ' + value["public_key"] + "\n"


def metadata(value):
    result = strict_json(canonical(value))
    keys(result, ("author", "committer", "timestamp", "timezone", "message"))
    for field in ("author", "committer"):
        item = result[field]
        keys(item, ("name", "email"))
        name = _text(item["name"], 128)
        email = _text(item["email"], 254, ascii_only=True)
        if (
            any(c in name for c in "<>")
            or any(c in email for c in "<>")
            or any(c.isspace() for c in email)
        ):
            raise PlanError("invalid Git identity")
        if email.count("@") != 1 or email.startswith("@") or email.endswith("@"):
            raise PlanError("invalid Git email identity")
    timestamp = result["timestamp"]
    if (
        type(timestamp) is not int
        or not 0 <= timestamp <= 4102444800
        or result["timezone"] != "+0000"
    ):
        raise PlanError("invalid fixed Git timestamp")
    message = result["message"]
    if not isinstance(message, str) or not 0 < len(message.encode("utf-8")) <= 16384:
        raise PlanError("invalid commit message size")
    if "\x00" in message or "\r" in message:
        raise PlanError("invalid commit message control")
    return result


def message(prepared):
    meta = prepared["commit_metadata"]
    db = prepared["plan"]["preconditions"]["db"]
    return (
        meta["message"]
        + "\n\nYamora-GitOps-Intent: "
        + prepared["intent_id"]
        + "\nYamora-Plan: "
        + prepared["plan_id"]
        + "\nYamora-Operation: "
        + prepared["operation_id"]
        + "\nYamora-Export: "
        + db["export_sha256"]
        + "\nYamora-Source-Revision: "
        + db["revision"]
        + "\n"
    ).encode("utf-8")


def identity_environment(meta):
    return {
        "GIT_" + label + "_" + field: (
            "@" + str(meta["timestamp"]) + " " + meta["timezone"]
            if field == "DATE"
            else meta[who][field.lower()]
        )
        for label, who in (("AUTHOR", "author"), ("COMMITTER", "committer"))
        for field in ("NAME", "EMAIL", "DATE")
    }


@contextmanager
def private_key(config, writer):
    if writer.ssh_binary is None:
        raise GitInfrastructureError("optional ssh-keygen signing tool is unavailable")
    keys(config, ("private_key_file",))
    path = _text(config["private_key_file"], 4096)
    if not os.path.isabs(path):
        raise PlanError("signing key path must be absolute")
    path = plain_path(path, directory=False)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        current = path.stat()
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_nlink != 1:
            raise PlanError("signing key must be an owned regular file")
        if stat.S_IMODE(s.st_mode) not in (0o400, 0o600) or not 0 < s.st_size <= 16384:
            raise PlanError("signing key protection or size is invalid")
        if (s.st_dev, s.st_ino) != (current.st_dev, current.st_ino):
            raise PlanError("signing key identity changed")
        yield "/proc/" + str(os.getpid()) + "/fd/" + str(fd)
    finally:
        if not writer.retained:
            os.close(fd)
        # On unverified stop the descriptor remains pinned until process teardown.


def check_commit(raw, prepared, tree_oid):
    if not isinstance(raw, bytes) or len(raw) > MAX_COMMIT:
        raise PlanError("invalid signed commit size")
    meta = prepared["commit_metadata"]
    expected = [
        b"tree " + tree_oid.encode("ascii"),
        b"parent " + prepared["expected_old_commit"].encode("ascii"),
    ]
    for field in ("author", "committer"):
        ident = meta[field]
        expected.append(
            (
                field
                + " "
                + ident["name"]
                + " <"
                + ident["email"]
                + "> "
                + str(meta["timestamp"])
                + " "
                + meta["timezone"]
            ).encode("utf-8")
        )
    header, separator, body = raw.partition(b"\n\n")
    if not separator or body != message(prepared):
        raise PlanError("signed commit message differs from frozen intent")
    rows = header.split(b"\n")
    signature_header = (
        b"gpgsig " if prepared["repository"]["object_format"] == "sha1" else b"gpgsig-sha256 "
    )
    if rows[:4] != expected or len(rows) < 6 or not rows[4].startswith(signature_header):
        raise PlanError("signed commit tree/parent/identity differs from frozen intent")
    signature = rows[4][len(signature_header) :] + b"\n"
    for row in rows[5:]:
        if not row.startswith(b" "):
            raise PlanError("unexpected signed commit header")
        signature += row[1:] + b"\n"
    if (
        len(signature) > 16384
        or not signature.startswith(b"-----BEGIN SSH SIGNATURE-----\n")
        or not signature.endswith(b"-----END SSH SIGNATURE-----\n")
    ):
        raise PlanError("invalid SSH signature envelope")
