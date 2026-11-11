# Log controls

I put **Auto-delete logs** and **Delete saved logs now** in Settings, under
Logging. The log window also has **Delete saved logs**, alongside a separate
**Clear display** button. Deletion needs confirmation and uses the saved log
path; typing a different path in Settings doesn't quietly change its target.

The age choices are **0, 5, 10, 12, 15, 22, 28, 30 and 60 days**. **0 is off**.
Normal size-based rotation still applies when age-based deletion is off.
The setting survives a restart. New configurations use the user's application
data folder for logs. Existing configured paths stay as they are.

I clear the configured file and its exact `.1` backup. I don't scan folders or
include certificates, trusted peers, exported copies or system logs. I don't
discover other applications' logs. The files stay in place, empty, so logging can carry on.
A running writer may add a new entry straight after deletion. Manual deletion
also clears the display after the saved logs have been cleared successfully.

Age is measured from the oldest entry in each file. Once due, I clear that
**whole file**, including newer lines in it. Existing timestamped logs remain
readable; newly created logs have an explicit age marker. Rotation preserves
that age. The display has its own age and a 5,000-line limit.

The GUI and a file-logging engine each check once a minute, and on startup;
the engine also checks before writing. This works with the GUI closed if the
engine is still logging. Nothing runs while both are stopped, so overdue logs
are cleared at the next start. Changing file logging, its path or retention
restarts running sharing briefly so the engine receives the saved choice.
The command-line equivalent is `--log-retention-days 5` alongside `--log FILE`.

I validate and lock the opened files before clearing them. Unknown contents,
unsafe ownership, writable POSIX ancestors, links, files above 2 MiB and busy
files are refused with an error. If a later disk operation fails, one file may
already have been cleared; the error deliberately doesn't promise a rollback.
On Windows, existing files must already have a protected owner/LocalSystem
ACL; broad inherited permissions are refused rather than silently rewritten.
Ordinary users cannot clear service-owned logs without the existing required
access. There's no new privileged deletion command.

This removes application-visible contents. It isn't secure erasure of disk
blocks, snapshots or backups. POSIX mode checks don't cover every extended ACL;
Windows ancestor handling and native Windows/macOS integration still need
review. I'd like those checked before treating this as release-ready privacy
housekeeping. The filesystem always gets a vote.

## Windows checks

The standalone `native-log-store` target exercises the production log store
without Qt or OpenSSL. It covers all age choices, current/backup deletion and
continued writing, busy files, unknown contents, broad and inherited ACL
refusal, links, streams, size limits, Unicode names, rotation, legacy logs and
handle inheritance. The existing foreign-owner fixture also checks the log
editor. These tests are added in 2.4.36; native execution is pending at this
source checkpoint. The macOS workflow also includes the existing portable
retention suite. Both selections subsequently pass on 2.4.36: Windows run
42981547370 and macOS run 42981547400.

In 2.4.37 I extend the temporary LocalSystem service fixture to cover logs too:
retention, manual clearing, resumed writing, console-owner policy, foreign-owner
refusal, unavailable console tokens, denied writes and busy files. It checks
preserved bytes and ACLs after refusal, and prevents the ordinary test process
from reading the service-owned log. Windows run 42993099755 passes these checks,
including the active console-user case. This isn't an installed-application or
interactive GUI check.

In 2.4.38 Windows log access shares the private-file parent walk and refuses
reparse points. Native run 43103242776 passes linked-parent refusal but proves
that an open directory handle doesn't pin its name against a same-user rename.
Version 2.4.39 therefore checks owner and ACL entries for unsafe writers and
rechecks each component's volume and file identity around the final operation.
Native run 43105163943 compiles this, then refuses the runner's shared temporary
ancestry. Version 2.4.40 moves native fixtures under private Local AppData while
retaining the explicit broad-parent refusal case. Execution is pending. The
directory owner still controls its folder, and inherited deny-ACE policy remains
under review.
