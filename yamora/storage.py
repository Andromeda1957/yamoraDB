"""Descriptor-pinned, fsynced publication for YamoraDB authoring tools."""

import os
import secrets
import stat
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING or __package__:
    from .validation import ValidationError
else:
    from validation import ValidationError


def write_all(descriptor, payload):
    used = 0
    while used < len(payload):
        written = os.write(descriptor, payload[used:])
        if written <= 0:
            raise OSError("write made no progress")
        used += written


def atomic_write_directory(directory_fd, filename, payload, *, replace):
    try:
        metadata = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        metadata = None
    if metadata is not None:
        if not stat.S_ISREG(metadata.st_mode):
            raise ValidationError("destination is not a regular file")
        if not replace:
            raise ValidationError("destination exists; pass --replace to overwrite it")
    temporary = f".yamldbctl-{os.getpid()}-{secrets.token_hex(8)}"
    descriptor = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o644,
            dir_fd=directory_fd,
        )
        write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        if replace:
            os.replace(temporary, filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        else:
            os.link(
                temporary,
                filename,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            os.unlink(temporary, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise


def atomic_write_path(path, payload, *, replace):
    target = Path(path)
    parent = target.parent if str(target.parent) else Path(".")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_fd = os.open(parent, flags)
    try:
        atomic_write_directory(directory_fd, target.name, payload, replace=replace)
    finally:
        os.close(directory_fd)
