# Log deletion review, 2.4.35

11 November 2026. I review the logging change against `2476ef8d`, covering
`LogStore`, the file-outputter thread, GUI settings/deletion, retention arguments
and the Windows editing helper. This is a scoped source review, not a complete
security audit or release clearance.

I keep deletion to the saved configured filename and exact `.1` backup.
Both files are opened and validated before manual clearing starts. Truncation
uses held descriptors; it doesn't unlink an active writer's file. Reads and
entries are bounded, rotation preserves the file's age and non-blocking locks
refuse an already busy file. Failures are reported without logging recursively
from the cleanup thread. The GUI asks for confirmation and separates saved-log
deletion from clearing its display.

POSIX checks include each parent, final ownership, regular-file type, link count,
write permissions and size. Recognised files are restricted to mode 0600.
Windows editing requires an already protected owner/LocalSystem ACL; I don't
request ACL-write access or change permissions on unrecognised configured files.
Identity reads retain their existing explicit migration path. Native behaviour
still needs verification.

I find no new blocking defect by source inspection. The [build evidence](../../docs/build.md)
records eleven new storage cases, strict argument checks, five GUI cases, the
full local suite and selected ASan/UBSan checks. These aren't proof against every
filesystem failure or hostile same-user process.

## Limits and next checks

- Native Windows service/user access, Windows ancestors and macOS extended ACLs remain open.
- Disk errors can leave one file cleared before the second operation fails. I report incomplete deletion, not a fictitious rollback.
- Expiry clears whole files, including newer entries; nothing runs while all processes are stopped.
- This isn't secure erasure of snapshots, backups, disk blocks or exported logs.
- Slow or remote log folders still use synchronous GUI file operations; check responsiveness before offering those paths as a supported workflow.
- Log display line limits don't yet impose a total byte cap; that remains BX-006.

No new dependency is introduced. Existing runtime inventory, advisory disposition,
packaging and native checks remain in [dependencies.md](../../docs/dependencies.md)
and the preceding [security review](security-audit-2026-11-10-full.md). I don't
close those items because log housekeeping now works.
