# Local management access

I traced this boundary for 2.4.12-snapshot on 2 November 2026. Caller
authentication is unfinished. The role checks below cannot identify a user.

## Current paths

| Component | Observed behaviour | Remaining boundary |
| --- | --- | --- |
| Qt IpcClient | Connects to 127.0.0.1:24801, sends a GUI greeting and command/elevation frames | I have no credential exchange or proof of service identity |
| Engine IpcClient | Sends a node greeting and receives service messages, including shutdown | I have no proof that a node is the child launched by the service |
| IpcClientProxy | Requires one greeting; only a declared GUI can dispatch commands; duplicate greetings close the connection | Any local process can declare either role |
| IpcServer/IpcLogOutputter | Select log recipients by declared role | Log access still has no authenticated principal |
| Windows DaemonApp | Parses commands, changes logging, saves Command/Elevate in system settings and calls setCommand | I must authorise every effect before changing settings or launching |
| MSWindowsWatchdog | Launches in the active session; explicit elevation or a non-default desktop selects a privileged token path | I must constrain executable selection and review the desktop/elevation policy |
| ArchSystemWindows | Stores settings beneath HKEY_LOCAL_MACHINE\SOFTWARE\Barrier | I still need to verify installed registry ACLs and saved-command handling |

The common proxy is exercised on Linux. The service/watchdog path is Windows
code; Linux protocol tests cannot establish its token or ACL behaviour.

## Proposed native channel

I favour a Windows named pipe for this service boundary, with an explicit DACL,
remote-client rejection and caller token/session checks before dispatch. This
is a proposal, not an implemented transport. The default pipe descriptor allows
Everyone and anonymous read access, which is unsuitable for service logs.

I need separate permissions for log subscription, engine shutdown participation,
command changes and elevation. A GUI role alone grants none of these in the
proposed design. The token's logon/session identity must match the authorised
interactive session. Engine access needs a binding to the service's retained
child-process identity. Service identity must also be checked by clients;
knowing a pipe name proves very little.

If impersonation is used to inspect a caller, I must check its result, refuse
requests when identity lookup fails and restore the original thread context on
every exit. The verified principal must remain attached to the queued request,
so the daemon can apply policy before registry, log-file or process side effects.
An endpoint migration must not leave an unauthenticated TCP fallback accepting
the same operations. The GUI and engine clients must migrate together.

Before implementation I need a working Windows build/test job and a precise
policy for active-session users, administrators, service children and elevation.
I will also check which existing command options can load code or redirect
privileged file writes before defining an executable/argument allowlist.

## Required checks

I need live tests with an approved caller and a second local user: commands and
logs must be denied to the latter. Repeat across session switches, reconnects,
service restart, impersonation failure and a competing pipe server. Include
wrong-role requests from an otherwise valid caller. Saved commands need the
same executable policy when restored at service startup.

For the interface, I want permission rejection distinguished from a stopped
service (BX-007). A reconnect must not replay a stale command or request for
elevation without a current decision (BX-019). These behaviours remain proposals.

## Official references checked

I used Microsoft's [pipe security and access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
to check default access, logon SID restrictions and the extra instance-creation
right included in generic write access. I will choose specific rights for each
endpoint rather than inherit a broad default.

[CreateNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
documents PIPE_REJECT_REMOTE_CLIENTS. [ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
requires checking failure before executing client requests. I have not imported
sample code, changed dependencies or executed third-party scripts for this work.
