# Owned application workspaces

`src/consensus/application_workspace.h` owns descriptors and a narrow native
work-file reclamation capability for one compaction attempt. The controller supplies an existing
trusted parent descriptor, such as the archive store. Creation pins its own
parent descriptor, attempts `mkdirat` for a random 128-bit `.yamora-workspace-`
child with mode `0700`, then opens the child. `mkdirat` returns no inode: a
same-user replacement between creation and the first open cannot be detected
by a later stat/open comparison. Neither the name nor the opened descriptor
proves directory birth. The helper therefore never renames or deletes any
directory, including on successful native-file reclamation. Discard preserves
the initialization fence; explicit recycle can reclaim only its proven inode
after durable discard. The helper never creates the parent.

The `directory`, `parent`, and `name` accessors return borrowed values valid
through workspace close. Use the directory fd as the destination of
`yd_raft_application_copy_limited`. Admission can compare descriptor identities
to exclude this active workspace while counting its image separately. A name,
prefix, initialization fence, age, or missing process supplies no ownership or
disposal authority. The parent fd and name locate the opened shell; they are
not directory-birth evidence or a path-based cleanup capability. The pinned
parent remains the target if its external pathname is renamed or replaced.

## Controller sequence

1. Create the workspace under the pinned archive parent. Keep it alive through
   native copy, final catch-up, archive construction, and selector decision.
2. After the final successful image operation, call
   `yd_raft_application_workspace_bind(workspace, image, error, length)` while
   the image is alive. Bind checks the image's exact directory and both files
   against their creation descriptors and takes independent file descriptors.
   A failed image, foreign inode, missing file, link, or unknown entry rejects
   binding. Binding is allowed once per cycle. Perform no further image mutations after
   binding; a later changed physical file rejects disposal.
3. Obtain the parent's explicit outcome. Only
   `YD_RAFT_WORKSPACE_SAFE_PRESELECTION_SKIP` and
   `YD_RAFT_WORKSPACE_CONFIRMED_SUCCESS` permit discard. A skip must be known
   safe before artifact selection. Failed, stale, cancelled, or uncertain
   selectors, including failures after artifacts were created, preserve the
   workspace. `YD_RAFT_WORKSPACE_PRESERVE` and unrecognized values return `-1`
   without disposal. This helper does not classify selector outcomes.
4. Release the image, its readers, checkpoints, and any application captures
   of that private native file. Serialize all workspace methods and image
   operations; exclude selection and new pins throughout disposal. Independent
   native readers can continue using their pins until released.
5. Explicitly call `yd_raft_application_workspace_discard`. It returns `0`
   while a native or directory ownership lock is busy, `1` after durable
   reclamation of the proven native work file, or `-1` for invalid custody, a
   preserving outcome, or I/O failure. The fence and both directory shells
   remain at their names. This is not full workspace disposal.
   Retry partial disposal on the same handle with the same disposition.
6. To reuse the same two shells, separately call
   `yd_raft_application_workspace_recycle` after confirmed discard. It claims
   and verifies the proven fence, durably reclaims it, checks both shells empty,
   and releases the workspace directory lock before returning ready. Returns
   `1` ready, `0` busy or `-1` preserved/I/O; partial retries use the same handle.
   Another copy can then use that directory and bind a new successful image.
7. After all operations join, close the workspace. Close only releases
   descriptors, even after partial disposal. Discard closes the reclaimed native
   descriptor; recycle closes the reclaimed fence descriptor. Both directory
   descriptors remain until close.

## Exact custody and preservation

Native copy currently creates exactly `.yamora-disk` and the zero-length
`.yamora-initializing` fence. The successful copy retains that fence. There is
no third workspace manifest and no fence-based cleanup permission. Binding
requires both files to be private regular files owned by the effective user,
with one link each. Their open descriptors prevent inode reuse. Bind records
their inode, device, size, and modification time; it borrows no image pointer
and inherits no native flock.

Copy retains its `O_EXCL` fence descriptor until image close. Native open records
an immutable per-handle `created` fact from its actual `O_EXCL` open; pins and
reopens do not inherit that fact. Binding never requires the read-only image
pin's `created` flag. Copy rejects an existing native file before
any copy transaction can mutate it. The image's `created_files` check compares
the supplied directory, native, and fence descriptors with the original held
descriptors while the verified image is alive. An unrelated empty regular fence
is not accepted merely because its name and size resemble a copy fence.
Proven fence identity alone grants no cleanup authority. Recycle additionally
requires the same handle's completed durable discard and confirmed disposition.

Explicit disposal takes an independent exclusive native lock, so image readers,
physical checkpoints, and captures block cleanup even after image close. It
then takes the workspace directory lock. Following application retirement's
private-custody protocol for individual files, it attempts a random `0700`
`.discarding-workspace-` child of the same pinned parent and opens it. This
directory also has no birth proof and is preserved. Only the native file is
captured into its custody slot and verified after the rename before unlinking it. This
avoids unlinking a replacement inserted at a previously checked source name.

Both rename namespaces are synced before deletion. Every sync and rename
boundary is followed by identity/layout checks before the next destructive
step. A wrong object captured by a rename is returned with `RENAME_NOREPLACE`
when possible; otherwise it remains recoverable in custody. Such a contaminated
claim cannot become deletion authority on retry. Unknown or replaced contents,
symlinks, hard links, changed permissions, and changed parent trust stop disposal.
Partial unlink/sync failures retain precise in-memory progress, including names
already durably removed. Repeated successful discard is idempotent.

Production traversal examines only the exact workspace and custody directory,
with at most four entries including dots per check. It never scans siblings,
recurses, sweeps old directories, or reconstructs a capability after a crash.
Both directory shells remain. `workspace_account` can prove the exact named
workspace and optional empty custody against a supplied archive-root descriptor.
Only ready-empty or intact-bound states qualify; partially disposed states do
not. The controller's owned admission/select APIs check that proof before and
again after inventory. Custody is independently scanned as empty and stable;
there is no name/prefix exemption. Reusing this live capability bounds successful
cycles to two shells. Closing or crashing loses the capability: unknown shells
continue blocking admission. Full shell disposal, crash reconciliation, retention
and the automatic worker remain open.

The caller must guarantee cooperative exclusive ownership **inside the pinned
custody directory**, as in application retirement. There must be no arbitrary
same-UID mutation of that directory's entries during disposal. A directory fd
pins identity; advisory flock does not enforce namespace exclusion against an
uncooperative same-UID process. This is an explicit precondition, not a property
inferred from mode bits, birth, or a successful stat. Parent-namespace creation,
rename and replacement remain in scope: identity checks reject changed named
containers, preserve replacements and leave the native file intact when it has
not yet been reclaimed. In-place byte tampering with forged timestamps is outside
this metadata custody protocol.

## Verification

From the repository root, with an owned disk-backed `TMPDIR`, run
`python3 -m unittest yamora.tests.test_application_workspace`. Its real native
copies run under fatal ASan/UBSan. Scenarios cover explicit outcomes, copy and
catch-up cancellation, descriptor/pin lifetimes, no deletion on close, foreign
images, unknown contents, missing files, symlinks, hard links, creation faults,
same-user empty-directory swaps immediately after `mkdirat` and before the first
open for both helpers, empty replacement fences, inserted existing native files,
every disposal sync/rename/unlink fault, and replacements before and
after custody renames and at every sync boundary, eight repeated copy/recycle
cycles in the same shells, fence preservation, partial recycle and unlock
failure, and workspace/custody replacement at every recycle sync boundary.
The checkpoint concurrency
scenario also supports a fatal TSan build with instrumented OpenSSL.
