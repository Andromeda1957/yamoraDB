"""Real native encrypted-image qualification; no cloud credentials or owner data.

The combined candidate supplies the native image hooks. ENVELOPE_STORAGE_ENGINE_ROOT
may point to that candidate's yamora directory during coordinated qualification.
Default builds use fatal ASan/UBSan; ENVELOPE_SANITIZER=none selects normal C.
"""

import hashlib
import json
import os
import shlex
import signal
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptedNativeStorageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = os.environ.get("TMPDIR")
        if not scratch or not Path(scratch).is_dir():
            raise RuntimeError("an existing owned disk-backed TMPDIR is required")
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.yamora = Path(__file__).resolve().parents[1]
        cls.engine = Path(os.environ.get("ENVELOPE_STORAGE_ENGINE_ROOT", cls.yamora))
        cls.flags = [
            os.environ.get("CC", "clang"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-pthread",
            "-fno-omit-frame-pointer",
            "-fno-sanitize-recover=all",
            "-I" + str(cls.engine / "src"),
            "-I" + str(cls.yamora / "src"),
            "-I" + str(cls.yamora / "src/security"),
        ]
        sanitizer = os.environ.get("ENVELOPE_SANITIZER", "address,undefined")
        if sanitizer != "none":
            cls.flags += ["-fsanitize=" + sanitizer]
        cls.libraries = shlex.split(
            subprocess.run(
                ["pkg-config", "--cflags", "--libs", "openssl", "yaml-0.1"],
                capture_output=True,
                text=True,
                check=True,
                timeout=15,
            ).stdout
        ) + ["-lm"]
        cls.wraps = [
            "-Wl,--wrap=" + name
            for name in ("fsync", "pwrite", "renameat", "mlock2", "madvise", "yd_key_provider_free")
        ]
        # Exercise the production native-library closure. A directory glob also
        # picks up standalone consensus capture units that the native library
        # does not link and whose Raft dependencies are outside this profile.
        production_sources = subprocess.run(
            [
                "make",
                "-C",
                str(cls.engine),
                "--no-print-directory",
                "--silent",
                "--eval=encrypted-test-sources:;@echo $(LIB_SOURCE)",
                "encrypted-test-sources",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
        ).stdout
        sources = [cls.engine / name for name in shlex.split(production_sources)]
        if not sources or any(not source.is_file() for source in sources):
            raise RuntimeError("production native-library sources unavailable")
        sources += [
            cls.yamora / "src/security" / name
            for name in (
                "envelope.c",
                "key_provider.c",
                "oidc_json.c",
                "storage_image.c",
                "storage_config.c",
            )
        ]
        sources += [cls.yamora / "tests/envelope_storage_harness.c"]
        cls.objects = {}
        for index, source in enumerate(sources):
            target = cls.root / f"object-{index}.o"
            cls.compile(source, target)
            # Preserve both root and sharding aggregate translation units.
            key = source.name if source.name not in cls.objects else str(source)
            cls.objects[key] = target
        cls.binary = cls.link("encrypted-native")

    @classmethod
    def compile(cls, source, target):
        result = subprocess.run(
            cls.flags + ["-c", str(source), "-o", str(target)],
            capture_output=True,
            text=True,
            timeout=90,
        )
        if result.returncode:
            raise RuntimeError(f"native encrypted-image compile failed: {source}\n{result.stderr}")

    @classmethod
    def link(cls, name, replacements=None):
        objects = dict(cls.objects)
        objects.update(replacements or {})
        target = cls.root / name
        result = subprocess.run(
            cls.flags
            + list(map(str, objects.values()))
            + cls.wraps
            + cls.libraries
            + ["-o", str(target)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode:
            raise RuntimeError("native encrypted-image link failed:\n" + result.stderr)
        return target

    def directory(self, name):
        path = self.root / f"{self._testMethodName}-{name}"
        path.mkdir(mode=0o700)
        return path

    def invoke(self, root, mode, generation, *extra, expected=0, binary=None, **environment):
        result = subprocess.run(
            [str(binary or self.binary), str(root), mode, str(generation), *map(str, extra)],
            capture_output=True,
            text=True,
            timeout=30,
            env=dict(
                os.environ,
                ASAN_OPTIONS=f"detect_leaks={int(expected == 0)}:halt_on_error=1",
                UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1",
                **environment,
            ),
        )
        self.assertEqual(result.returncode, expected, result.stderr)
        self.assertNotIn("Sanitizer", result.stderr)
        self.assertNotIn("runtime error:", result.stderr)
        return result

    def seed(self, name="source", binary=None):
        root = self.directory(name)
        self.assertEqual(self.invoke(root, "seed", 1, binary=binary).stdout.strip(), "5")
        return root

    @staticmethod
    def configuration():
        return {
            "version": 1,
            "mode": "create",
            "store_id": "a1" * 16,
            "object_id": "b2" * 32,
            "generation": 1,
            "maximum_bytes": 1024 * 1024,
            "cache_bytes": 32768,
            "key_id": "image-key-1",
            "provider": {
                "type": "local",
                "keys": [
                    {"id": "image-key-1", "key_hex": "51" * 32},
                    {"id": "image-key-2", "key_hex": "62" * 32},
                ],
            },
        }

    def config_file(self, name, config=None, raw=None):
        path = self.root / f"{self._testMethodName}-{name}.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(raw if raw is not None else json.dumps(config))
        return path

    def assert_encrypted_files(self, root):
        for path in root.rglob("*"):
            if path.is_file():
                wire = path.read_bytes()
                for secret in (
                    b"authored comment",
                    b"replacement comment",
                    b"EXACT-BYTES",
                    b"STORAGE-RECEIPT",
                    b"YAMDIS05",
                    b"YDBTREE2",
                    b"YDBLOB02",
                ):
                    self.assertNotIn(secret, wire, str(path))
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    @staticmethod
    def plaintext(wire, kek=bytes([0x51]) * 32):
        key_length, wrapped_length = struct.unpack(">HH", wire[36:40])
        metadata = bytearray(wire[:128])
        metadata[38:40] = b"\0\0"
        key_id = wire[128 : 128 + key_length]
        context = hashlib.sha256(metadata + key_id).digest()
        start = 128 + key_length
        wrapped = wire[start : start + wrapped_length]
        dek = AESGCM(kek).decrypt(wrapped[:12], wrapped[12:], context)
        start += wrapped_length
        return AESGCM(dek).decrypt(wire[88:100], wire[start:], wire[:start])

    @staticmethod
    def reseal_native_fixture(wire, plain):
        """Independent standard AESGCM fixture, with fresh DEK and both nonces."""
        metadata = bytearray(wire[:128])
        key_length = int.from_bytes(wire[36:38], "big")
        key_id = wire[128 : 128 + key_length]
        metadata[20:24] = len(plain).to_bytes(4, "big")
        metadata[38:40] = bytes(2)
        metadata[88:100] = os.urandom(12)
        context = hashlib.sha256(metadata + key_id).digest()
        dek, wrap_nonce = os.urandom(32), os.urandom(12)
        wrapped = wrap_nonce + AESGCM(bytes([0x51]) * 32).encrypt(wrap_nonce, dek, context)
        metadata[38:40] = len(wrapped).to_bytes(2, "big")
        aad = bytes(metadata) + key_id + wrapped
        return aad + AESGCM(dek).encrypt(bytes(metadata[88:100]), bytes(plain), aad)

    @staticmethod
    def crc32c(data):
        value = 0xFFFFFFFF
        for byte in data:
            value ^= byte
            for _ in range(8):
                value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
        return value ^ 0xFFFFFFFF

    def test_native_documents_indexes_hidden_records_and_independent_decryption(self):
        root = self.seed()
        self.invoke(root, "read-old", 5)
        self.assert_encrypted_files(root)
        plain = self.plaintext((root / ".yamora-disk").read_bytes())
        self.assertEqual(plain[:8], b"YAMDIS05")
        self.assertIn(
            "# authored comment\nname: 'café'\nrating: 7\nbody: |\n  ENCRYPTED-STORAGE-EXACT-BYTES\n".encode(),
            plain,
        )
        self.assertIn(b"ENCRYPTED-STORAGE-RECEIPT\0binary", plain)

    def test_real_replica_staging_cipher_checkpoint_backup_and_restore(self):
        root = self.seed()
        backup, restored = self.directory("backup"), self.directory("restored")
        old = (root / ".yamora-disk").read_bytes()
        self.assertEqual(self.invoke(root, "stage-backup", 5, backup).stdout.strip(), "6")
        self.assertEqual((backup / ".yamora-disk").read_bytes(), old)
        self.invoke(root, "read-new", 6)
        self.invoke(backup, "read-old", 5)
        self.invoke(backup, "restore", 5, restored)
        self.invoke(restored, "read-old", 5)
        self.assertEqual((restored / ".yamora-disk").read_bytes(), old)
        for artifact in (root, backup, restored):
            self.assert_encrypted_files(artifact)

    def test_key_loss_wrong_key_rotation_and_historical_backup_keys(self):
        root = self.seed()
        backup = self.directory("backup")
        self.invoke(root, "stage-backup", 5, backup)
        self.invoke(root, "wrong", 6)
        self.invoke(root, "missing", 6)
        self.assertEqual(self.invoke(root, "rotate", 6).stdout.strip(), "7")
        self.invoke(root, "read-key2", 7)
        self.invoke(root, "refuse", 6)
        self.invoke(backup, "missing", 5)
        self.invoke(backup, "read-old", 5)
        self.assert_encrypted_files(root)

    def test_tampering_truncation_relocation_and_exact_generation_refuse_unchanged(self):
        root = self.seed()
        path = root / ".yamora-disk"
        original = path.read_bytes()
        self.invoke(root, "relocation", 5)
        self.invoke(root, "refuse", 4)
        self.invoke(root, "refuse", 6)
        for index in (0, 24, 40, 56, 88, 128, len(original) // 2, len(original) - 1):
            mutated = bytearray(original)
            mutated[index] ^= 1
            path.write_bytes(mutated)
            self.invoke(root, "refuse", 5)
            self.assertEqual(path.read_bytes(), mutated)
        for size in (0, 127, 8192, len(original) - 1):
            path.write_bytes(original[:size])
            self.invoke(root, "refuse", 5)
            self.assertEqual(path.read_bytes(), original[:size])
        path.write_bytes(original)
        self.invoke(root, "read-old", 5)

    def test_plaintext_exports_refuse_and_pin_retains_memory_namespace_custody(self):
        root = self.seed()
        self.assertEqual(self.invoke(root, "guards", 5).stdout.strip(), "6")
        self.assert_encrypted_files(root)

    def test_concurrent_native_writers_pinned_history_and_encrypted_restart(self):
        root = self.seed()
        self.assertEqual(self.invoke(root, "concurrent", 5).stdout.strip(), "14")
        self.invoke(root, "read-workers", 14)
        self.assert_encrypted_files(root)

    def test_authenticated_schema_cluster_retention_and_truncated_native_images_refuse(self):
        root = self.seed()
        path = root / ".yamora-disk"
        wire = path.read_bytes()
        original = self.plaintext(wire)
        for profile in ("cluster", "schema", "retention", "truncated"):
            plain = bytearray(original if profile != "truncated" else original[:8192])
            for start in (0, 4096):
                if profile == "cluster":
                    plain[start : start + 8] = b"YAMDIS06"
                elif profile == "schema":
                    plain[start : start + 8] = b"YAMDIS07"
                    plain[start + 112 : start + 128] = b"YDSCHEM1" + struct.pack("<II", 1, 1)
                elif profile == "retention":
                    plain[start + 64 : start + 112] = (
                        b"YDOFENC1" + struct.pack("<II", 1, 1) + bytes([1]) * 32
                    )
                else:
                    plain[start : start + 4096] = bytes(4096)
                    plain[start : start + 8] = b"YAMDIS05"
                    struct.pack_into("<QQQ", plain, start + 8, 1, 0, 16384)
                struct.pack_into(
                    "<I", plain, start + 4092, self.crc32c(plain[start : start + 4092])
                )
            candidate = self.reseal_native_fixture(wire, plain)
            self.assertEqual(self.plaintext(candidate), plain)
            path.write_bytes(candidate)
            self.invoke(root, "refuse", 5)
            self.assertEqual(path.read_bytes(), candidate)
        path.write_bytes(wire)
        self.invoke(root, "read-old", 5)

    def test_locked_memory_and_dontdump_admission_fail_without_files(self):
        for mode in ("mlock", "dontdump"):
            root = self.directory(mode)
            self.invoke(root, mode, 1)
            self.assertEqual(list(root.iterdir()), [])

    def test_private_config_native_start_restart_and_provider_lifetime_through_pin(self):
        root = self.directory("source")
        config = self.configuration()
        path = self.config_file("create", config)
        self.assertEqual(self.invoke(root, "config-seed", 1, path).stdout.strip(), "2")
        self.assert_encrypted_files(root)
        config.update(mode="open", generation=2)
        opened = self.config_file("open", config)
        self.assertEqual(self.invoke(root, "config-read", 2, opened).stdout.strip(), "2")
        self.assertEqual(self.invoke(root, "config-pin", 2, opened).stdout.strip(), "2")
        config["generation"] = 1
        stale = self.config_file("stale", config)
        self.invoke(root, "config-refuse", 1, stale)

    def test_config_rejects_malformed_unknown_duplicate_or_unusable_values_before_files(self):
        cases = [
            ("version", 2),
            ("mode", "auto"),
            ("mode", True),
            ("generation", 0),
            ("generation", -1),
            ("generation", 18446744073709551616),
            ("generation", 1.5),
            ("maximum_bytes", 8193),
            ("maximum_bytes", 64 * 1024 * 1024 + 4096),
            ("cache_bytes", 1),
            ("store_id", "00" * 16),
            ("object_id", "B2" * 32),
            ("key_id", "missing-write-key"),
            ("unexpected", "secret-marker"),
            ("provider", {"type": "local", "keys": []}),
            (
                "provider",
                {
                    "type": "local",
                    "keys": [
                        {"id": "image-key-1", "key_hex": "51" * 32},
                        {"id": "image-key-1", "key_hex": "62" * 32},
                    ],
                },
            ),
            ("provider", {"type": "local", "keys": [{"id": "image-key-1", "key_hex": "ZZ" * 32}]}),
            (
                "provider",
                {
                    "type": "local",
                    "keys": [{"id": "image-key-1", "key_hex": "51" * 32, "extra": "secret-marker"}],
                },
            ),
        ]
        for index, (field, value) in enumerate(cases):
            root = self.directory(str(index))
            config = self.configuration()
            config[field] = value
            path = self.config_file(str(index), config)
            result = self.invoke(root, "config-refuse", 1, path)
            self.assertNotIn("secret-marker", result.stderr)
            self.assertEqual(list(root.iterdir()), [])
        for index, raw in enumerate(
            (
                "{}",
                "{",
                '{"version":1,"version":1}',
                json.dumps(self.configuration()).replace('"generation": 1', '"generation": 1e0'),
            )
        ):
            root = self.directory(f"raw-{index}")
            path = self.config_file(f"raw-{index}", raw=raw)
            self.invoke(root, "config-refuse", 1, path)
            self.assertEqual(list(root.iterdir()), [])

    def test_config_file_identity_permissions_type_bound_and_cancellation_refuse(self):
        config = self.configuration()
        for mode in (
            "symlink",
            "hardlink",
            "permissions",
            "oversize",
            "fifo",
            "directory",
            "cancel",
        ):
            root = self.directory(mode)
            path = self.config_file(mode, config)
            if mode == "symlink":
                link = path.with_suffix(".link")
                link.symlink_to(path)
                path = link
            elif mode == "hardlink":
                os.link(path, path.with_suffix(".link"))
            elif mode == "permissions":
                path.chmod(0o644)
            elif mode == "oversize":
                path.write_text(" " * 16385)
            elif mode == "fifo":
                path.unlink()
                os.mkfifo(path, 0o600)
            elif mode == "directory":
                path.unlink()
                path.mkdir(mode=0o700)
            self.invoke(root, "config-cancel" if mode == "cancel" else "config-refuse", 1, path)
            self.assertEqual(list(root.iterdir()), [])

    def test_config_remote_adapters_without_trusted_transport_refuse_before_files(self):
        for name, provider, key_id in (
            (
                "aws",
                {
                    "type": "aws-kms",
                    "key_arn": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
                },
                "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
            ),
            (
                "vault",
                {
                    "type": "vault-transit",
                    "mount": "transit",
                    "name": "image-key-1",
                    "write_version": 1,
                },
                "image-key-1",
            ),
        ):
            root = self.directory(name)
            config = self.configuration()
            config.update(provider=provider, key_id=key_id)
            path = self.config_file(name, config)
            self.invoke(root, "config-refuse", 1, path)
            self.assertEqual(list(root.iterdir()), [])

    def test_publication_failures_fence_writer_and_never_acknowledge(self):
        for fault in (
            "enospc",
            "file-sync",
            "rename",
            "directory-sync",
            "silent-corruption",
            "post-rename-corruption",
        ):
            root = self.seed(fault)
            original = (root / ".yamora-disk").read_bytes()
            self.invoke(root, "write-fault", 5, fault)
            self.assert_encrypted_files(root)
            if fault not in ("directory-sync", "post-rename-corruption"):
                self.assertEqual((root / ".yamora-disk").read_bytes(), original)
                self.invoke(root, "read-old", 5)
            elif fault == "directory-sync":
                self.invoke(root, "read-new", 6)
            else:
                self.invoke(root, "refuse", 6)

    def test_backup_rejects_lost_name_changed_root_and_corrupt_delivered_bytes(self):
        root = self.seed()
        for fault in ("backup-unlink", "backup-root-mode", "silent-corruption"):
            destination = self.directory(fault)
            self.invoke(root, "backup-fault", 5, destination, fault)
        self.invoke(root, "read-old", 5)

    def test_sigkill_at_each_ciphertext_publication_boundary(self):
        for stage in range(1, 7):
            root = self.seed(str(stage))
            self.invoke(root, "kill", 5, stage, expected=-signal.SIGKILL)
            self.invoke(root, "read-new" if stage >= 4 else "read-old", 6 if stage >= 4 else 5)
            self.assert_encrypted_files(root)

    def test_durable_file_and_namespace_replay_at_every_completed_io_prefix(self):
        root = self.seed()
        old = (root / ".yamora-disk").read_bytes()
        trace = self.root / "encrypted-native-io.trace"
        self.invoke(root, "change", 5, ENVELOPE_STORAGE_TRACE=str(trace))
        data = trace.read_bytes()
        at, working, durable = 0, bytearray(), None
        selected, generation, renamed, synced = old, 5, False, False
        prefixes = 0
        while at < len(data):
            kind, offset, size = struct.unpack("<cQQ", data[at : at + 17])
            at += 17
            payload = data[at : at + size]
            at += size
            if kind == b"W":
                working.extend(bytes(max(0, offset + size - len(working))))
                working[offset : offset + size] = payload
            elif kind == b"F":
                durable = bytes(working)
            elif kind == b"R":
                self.assertIsNotNone(durable)
                renamed = True
                # Before directory sync, either old selection or the completed
                # rename may survive. Both admitted outcomes must be complete.
                uncertain = self.directory(f"prefix-{prefixes}-rename-survives")
                (uncertain / ".yamora-disk").write_bytes(durable)
                (uncertain / ".yamora-disk").chmod(0o600)
                self.invoke(uncertain, "read-new", 6)
            elif kind == b"D":
                self.assertTrue(renamed)
                selected, generation, synced = durable, 6, True
            else:
                self.fail(f"unexpected trace event {kind!r}")
            replay = self.directory(f"prefix-{prefixes}")
            (replay / ".yamora-disk").write_bytes(selected)
            (replay / ".yamora-disk").chmod(0o600)
            self.invoke(replay, "read-new" if generation == 6 else "read-old", generation)
            prefixes += 1
        self.assertTrue(synced)
        self.assertGreaterEqual(prefixes, 4)
        self.assertEqual(selected, (root / ".yamora-disk").read_bytes())

    def test_directory_sync_and_final_ciphertext_verification_mutants_are_red(self):
        source = (self.yamora / "src/security/storage_image.c").read_text()
        mutations = {
            "file-sync": ("!fsync(fd) && !fstat(fd, &s)", "!fstat(fd, &s)"),
            "directory-sync": ("!fsync(image->directory)", "true"),
            "final-verification": ("verified_cipher(fd, wire, size);", "true;"),
        }
        for name, (before, after) in mutations.items():
            self.assertIn(before, source)
            mutant = self.root / f"mutant-{name}.c"
            mutant.write_text(source.replace(before, after, 1))
            obj = self.root / f"mutant-{name}.o"
            self.compile(mutant, obj)
            binary = self.link(name, {"storage_image.c": obj})
            root = self.seed(name)
            if name in ("file-sync", "directory-sync"):
                self.invoke(root, "change", 5, expected=70, binary=binary)
            else:
                self.invoke(
                    root, "write-fault", 5, "post-rename-corruption", expected=70, binary=binary
                )
            restored = self.seed(name + "-restored")
            self.invoke(restored, "change", 5)

    def test_authenticated_length_guard_mutant_is_red_and_restored_green(self):
        source = (self.engine / "src/disk.c").read_text()
        before = "fence_pair(fd, authenticated_length, slots, valid, &fence, &schema, NULL)"
        self.assertIn(before, source)
        mutant = self.root / "mutant-authenticated-length.c"
        mutant.write_text(
            source.replace(before, before.replace("authenticated_length", "limit"), 1)
        )
        obj = self.root / "mutant-authenticated-length.o"
        self.compile(mutant, obj)
        binary = self.link("authenticated-length", {"disk.c": obj})
        root = self.seed()
        path = root / ".yamora-disk"
        plain = bytearray(8192)
        for start in (0, 4096):
            plain[start : start + 8] = b"YAMDIS05"
            struct.pack_into("<QQQ", plain, start + 8, 1, 0, 16384)
            struct.pack_into("<I", plain, start + 4092, self.crc32c(plain[start : start + 4092]))
        path.write_bytes(self.reseal_native_fixture(path.read_bytes(), plain))
        self.invoke(root, "refuse", 5, expected=70, binary=binary)
        self.invoke(root, "refuse", 5)

    def test_native_durable_publication_callback_mutant_is_red_and_restored_green(self):
        source = (self.engine / "src/disk.c").read_text()
        before = (
            "valid = disk->image.publish(disk->image.context, disk->fd, &txn->view, error, length);"
        )
        self.assertIn(before, source)
        mutant = self.root / "mutant-native-publication.c"
        mutant.write_text(source.replace(before, "valid = true;", 1))
        obj = self.root / "mutant-native-publication.o"
        self.compile(mutant, obj)
        binary = self.link("native-publication", {"disk.c": obj})
        root = self.seed()
        self.invoke(root, "write-fault", 5, "file-sync", expected=70, binary=binary)
        self.invoke(root, "write-fault", 5, "file-sync")


if __name__ == "__main__":
    unittest.main()
