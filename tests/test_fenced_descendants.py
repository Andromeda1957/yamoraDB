"""Fenced descendant lifetime with real kernel exclusion and fatal sanitizers."""

import unittest

from yamora.tests import test_native_open_fence as opening

ROOT = opening.ROOT


class FencedDescendantsTests(unittest.TestCase):
    harness = ROOT / "tests/fenced_descendants.c"
    setUpClass = classmethod(opening.NativeOpenFenceTests.setUpClass.__func__)
    compiler = classmethod(opening.NativeOpenFenceTests.compiler.__func__)
    embedded = True

    @classmethod
    def compile(cls, binary, replacement=None, tree=None):
        objects = dict(cls.objects)
        if tree:
            obj = cls.build / (binary.name + "-tree.o")
            cls.compiler([*cls.flags, "-c", str(tree), "-o", str(obj)])
            objects["disk_tree.c"] = obj
        cls.compiler(
            [
                *cls.flags,
                '-DFENCED_DISK_SOURCE="' + str(replacement or ROOT / "src/disk.c") + '"',
                str(cls.harness),
                *map(str, objects.values()),
                *[
                    "-Wl,--wrap=" + name
                    for name in (
                        "fsync",
                        "pwrite",
                        "pread",
                        "fcntl",
                        "calloc",
                        "fstat",
                        "pthread_mutex_init",
                        "pthread_cond_init",
                        "pthread_mutex_lock",
                        "pthread_mutex_unlock",
                        "yd_disk_process_valid",
                    )
                ],
                "-pthread",
                *cls.crypto,
                "-lyaml",
                "-lm",
                "-o",
                str(binary),
            ]
        )
        return binary

    run_case = opening.NativeOpenFenceTests.run_case

    def scenario(self, name):
        result = self.run_case(name)
        self.assertEqual(
            (result.returncode, result.stdout, result.stderr),
            (0, "FENCED_DESCENDANTS_OK\n", ""),
        )

    def test_pin_inherits_original_service_lifetime(self):
        self.scenario("pin")

    def test_unobserved_descendants_keep_real_kernel_exclusion(self):
        self.scenario("bare")

    def test_physical_capture_requires_original_inode_and_exact_fence(self):
        for case in ("binding", "fence-binding"):
            with self.subTest(case=case):
                self.scenario(case)

    def test_concurrent_writer_pins_and_saved_observation_reads(self):
        self.scenario("concurrent")

    def test_physical_root_clones_preserve_both_real_slots_and_fence(self):
        self.scenario("roots")

    def test_failed_writer_final_pair_is_actual_unacknowledged_publication(self):
        self.scenario("final")

    def test_exclusive_cut_observation_never_takes_shared_admission(self):
        self.scenario("cut")

    def test_snapshot_faults_and_pin_ownership_are_balanced(self):
        self.scenario("faults")

    def test_tracking_failure_is_sticky_while_producer_survives(self):
        self.scenario("tracking")

    def test_checked_holder_references_cannot_wrap_or_revive(self):
        self.scenario("references")

    def test_foreign_pid_rejects_before_actual_inherited_mutex(self):
        for case in ("fork", "scope-fork", "cache-fork"):
            with self.subTest(case=case):
                self.scenario(case)

    def test_cursor_free_does_not_dereference_closed_borrower(self):
        self.scenario("cursor-close")

    def test_foreign_pid_rejects_cached_cursor_without_io(self):
        self.scenario("cursor")

    def test_pending_cancellation_waits_for_adoption_and_balanced_cleanup(self):
        self.scenario("cancel")

    def test_preserving_descendants_hold_original_exclusion_without_repair(self):
        for case in ("preserve", "missing"):
            with self.subTest(case=case):
                self.scenario(case)

    def test_ambiguous_pairs_never_replace_saved_view_reads(self):
        for case in ("partial-eio", "partial", "mixed", "conflict", "damaged", "unknown"):
            with self.subTest(case=case):
                self.scenario(case)

    def test_precise_behavioral_mutants_and_restored_controls(self):
        disk = (ROOT / "src/disk.c").read_text()
        tree = (ROOT / "src/disk_tree.c").read_text()
        mutations = (
            (
                "pin-disabled",
                "pin",
                "FENCED_DESCENDANT_PIN_VALID",
                "disk",
                "bool held = fence_hold_get(source->fence_hold);",
                "bool held = false;",
            ),
            (
                "early-provider-release",
                "bare",
                "BARE_ORIGINAL_LEASE_SURVIVES",
                "disk",
                "    fence_hold_put(hold);\n    if (image.context) image.release(image.context);\n    (void)pthread_setcancelstate(prior, NULL);",
                "    if (hold && hold->service_owner) { hold->service_ops.release(hold->service_owner); hold->service_owner = NULL; }\n"
                "    fence_hold_put(hold);\n    if (image.context) image.release(image.context);\n    (void)pthread_setcancelstate(prior, NULL);",
            ),
            (
                "independent-pin-ofd",
                "bare",
                "NATIVE_OFD_THROUGH_ACTUAL_LAST_CLOSE",
                "disk",
                "int fd = held && image_held ? fcntl(source->fd, F_DUPFD_CLOEXEC, 0) : -1;\n    pthread_mutex_unlock",
                "int fd = held && image_held ? openat(source->fence_hold->namespace_lease, YD_DISK_FILE, O_RDONLY | O_CLOEXEC) : -1;\n    pthread_mutex_unlock",
            ),
            (
                "physical-fence-stripped",
                "roots",
                "PHYSICAL_ACTUAL_FENCE",
                "disk",
                "info->fence = fence;",
                "info->fence = (YDDiskOpenFence){0};",
            ),
            (
                "synthetic-pair",
                "roots",
                "PHYSICAL_ACTUAL_FENCE",
                "disk",
                "info->slots[slot].view = decoded[slot];",
                "info->slots[slot].view = decoded[0];",
            ),
            (
                "synthetic-final",
                "final",
                "FINAL_REAL_PAIR_WITH_FENCE",
                "disk",
                "bool known = recovery_headers(disk->fd, hold, &final);",
                "bool known = recovery_headers(disk->fd, hold, &final);\n"
                "        if (known) final.slots[final.selected].view = disk->view;",
            ),
            (
                "original-inode",
                "binding",
                "EXACT_ORIGINAL_NATIVE_INODE_REQUIRED",
                "disk",
                "status.st_ino != hold->inode",
                "false",
            ),
            (
                "original-fence",
                "fence-binding",
                "EXACT_ORIGINAL_FENCE_REQUIRED",
                "disk",
                "memcmp(&fence, &hold->fence, sizeof(fence))",
                "0",
            ),
            (
                "ambiguous-pair",
                "damaged",
                "AMBIGUOUS_PAIR_NEVER_COMPLETE",
                "disk",
                "if (!fence_pair(fd, info->file_size, decoded, valid, &fence, &schema, &fully_read) ||\n        !fully_read) return false;",
                "bool paired = fence_pair(fd, info->file_size, decoded, valid, &fence, &schema, &fully_read);\n"
                "    if (!fully_read) return false;\n"
                "    if (!paired && hold) fence = hold->fence;\n    else if (!paired) return false;",
            ),
            (
                "foreign-native",
                "fork",
                "FOREIGN_PID_BEFORE_INHERITED_MUTEX",
                "disk",
                "(!disk->fence_hold || disk->fence_hold->process == getpid());",
                "true;",
            ),
            (
                "foreign-scope",
                "scope-fork",
                "FOREIGN_PID_BEFORE_SCOPE_MUTEX",
                "disk",
                "if (!scope || scope->process != getpid()) return NULL;",
                "if (!scope) return NULL;",
            ),
            (
                "cached-cursor",
                "cursor",
                "FOREIGN_PID_CACHED_CURSOR_REFUSED",
                "tree",
                "!cursor || (cursor->process && cursor->process != getpid()) || cursor->failed",
                "!cursor || cursor->failed",
            ),
            (
                "cursor-borrower",
                "cursor-close",
                "CURSOR_FREE_INDEPENDENT_OF_CLOSED_BORROWER",
                "tree",
                "if (!cursor || (cursor->process && cursor->process != getpid()))",
                "if (!cursor || !yd_disk_process_valid(cursor->disk))",
            ),
            (
                "cancellable-adoption",
                "cancel",
                "CANCELLABLE_DESCENDANT_REFUSES_BEFORE_ADOPTION",
                "disk",
                "if (prior == PTHREAD_CANCEL_DISABLE) return true;\n    (void)pthread_setcancelstate(prior, NULL);\n    return false;\n}\nstruct YDDiskRecoveryRoots",
                "if (prior == PTHREAD_CANCEL_DISABLE || prior == PTHREAD_CANCEL_ENABLE) return true;\n    (void)pthread_setcancelstate(prior, NULL);\n    return false;\n}\nstruct YDDiskRecoveryRoots",
            ),
            (
                "pending-cancel",
                "cancel",
                "CANCELLATION_WAITS_FOR_ADOPTION",
                "disk",
                "if (prior == PTHREAD_CANCEL_DISABLE) return true;\n    (void)pthread_setcancelstate(prior, NULL);\n    return false;\n}\nstruct YDDiskRecoveryRoots",
                "if (prior == PTHREAD_CANCEL_DISABLE) { (void)pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL); pthread_testcancel(); return true; }\n    (void)pthread_setcancelstate(prior, NULL);\n    return false;\n}\nstruct YDDiskRecoveryRoots",
            ),
            (
                "reference-wrap",
                "references",
                "HOLDER_REFERENCE_WRAP_REFUSED",
                "disk",
                "while (count && count != SIZE_MAX)",
                "while (count)",
            ),
            (
                "reference-revival",
                "references",
                "HOLDER_ZERO_REFERENCE_NOT_REVIVED",
                "disk",
                "while (count && count != SIZE_MAX)",
                "while (count != SIZE_MAX)",
            ),
            (
                "tracking-loss",
                "tracking",
                "TRACKING_FAILURE_STICKY",
                "disk",
                "lineage_poison(scope, room ? YD_DISK_LINEAGE_LOST : YD_DISK_LINEAGE_LIMIT);",
                "(void)room;",
            ),
            (
                "snapshot-fault",
                "faults",
                "SNAPSHOT_FAULT_NEVER_FALSE_COMPLETE",
                "disk",
                "if (!snapshot->readers[i]) info->reasons |= YD_DISK_LINEAGE_IO;",
                "if (!snapshot->readers[i]) (void)info;",
            ),
            (
                "shared-admission-in-cut",
                "cut",
                "EX_CUT_OBSERVATION_NO_SHARED_ADMISSION",
                "disk",
                "bool held = fence_hold_get(sources[i]->fence_hold);",
                "if (sources[i]->fence_hold) {\n"
                "            int gatefd = openat(sources[i]->fence_hold->namespace_lease, YD_RETENTION_FILE, O_RDWR | O_CLOEXEC);\n"
                "            struct flock shared = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_len = 1};\n"
                "            if (gatefd < 0 || fcntl(gatefd, F_OFD_SETLKW, &shared)) info->reasons |= YD_DISK_LINEAGE_IO;\n"
                "            if (gatefd >= 0) close(gatefd);\n"
                "        }\n        bool held = fence_hold_get(sources[i]->fence_hold);",
            ),
        )
        for name, case, witness, unit, before, after in mutations:
            with self.subTest(mutant=name):
                original = tree if unit == "tree" else disk
                self.assertEqual(original.count(before), 1, "Mutant seam must be unique")
                source = self.build / ("mutant-" + name + ".c")
                source.write_text(original.replace(before, after, 1))
                binary = self.compile(
                    self.build / ("mutant-" + name),
                    source if unit == "disk" else None,
                    source if unit == "tree" else None,
                )
                red = self.run_case(case, binary)
                self.assertEqual(
                    (red.returncode, red.stdout, red.stderr),
                    (2, "", witness + "\n"),
                    "Only the exact normal assertion failure qualifies as RED",
                )
                self.scenario(case)
                print("DESCENDANT_RED/RESTORED_GREEN " + name + ": " + witness, flush=True)


if __name__ == "__main__":
    unittest.main()
