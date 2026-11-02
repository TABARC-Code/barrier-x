# Local management access

In 2.4.13 I use a Windows named pipe for the installed service, GUI and engine.
The service never opens a TCP management listener. The explicit-port TCP
constructors remain for the portable test harness; they do not supply command
credentials to DaemonApp.

## Current policy

| Request | Required identity |
| --- | --- |
| GUI greeting and log subscription | The active console user's SID, logon SID and session; restricted tokens are rejected |
| Command, logging configuration or elevation change | The same current logon with an enabled administrator token |
| Engine greeting and shutdown participation | The retained, live service child process in the active console session |
| Client connection to the service | Pipe server PID must match the running Barrier service reported by SCM |

I check Windows tokens after reading a fixed, bounded greeting. Anonymous or
failed identity queries are refused. Identification-level impersonation lets me
inspect credentials without giving the service permission to act as the caller.
A failed restoration of the service thread identity terminates the process.

The pipe DACL grants interactive callers specific data/attribute rights, without
the extra instance-creation right included in generic write access. SYSTEM and
administrators retain full control. I require the first server instance and
reject remote clients. A competing endpoint can deny startup, but clients refuse
to trust its process identity.

I compare UAC-linked logon identities where available, while retaining the actual
elevated token for command permission checks. A queued command keeps a shared
credential check, not a pointer to its former stream. The daemon checks it again
before touching logging, saved settings or the watchdog. Log writes recheck the
peer too. Disconnects and a changed console logon revoke later access.

I register the retained child handle before resuming a newly created engine.
PID reuse alone cannot identify a new trusted node, and replacing the registered
child revokes the previous node's permission. The stream has bounded input and
output queues, at most 24 retained authenticated peers and a three-second initial
greeting deadline. Pending overlapped I/O is cancelled and drained on stop.

## Upgrade and operation

I require the service, GUI and engine to be upgraded together. Older TCP clients
cannot configure the new service. The current console user can read service
logs without elevation, but must restart the interface as administrator to change
commands. Running the GUI as a different administrator account is not the same
console logon and is refused. Remote Desktop support is limited by the existing
console-session watchdog policy; I have not expanded that policy here.

The clients trust the installed service entry, not a foreground debugging
process. Registry Command/Elevate values remain machine settings. I restore them only
with the current approval marker, which the authenticated command path writes. Older
saved commands require administrator approval again, because their original
caller cannot be established. I invalidate the marker before updating either
value and publish approval after both saves succeed. Installation ACLs and
executable/argument allowlisting still need a separate deployment review. I have not claimed that
arbitrary administrator-supplied commands are sandboxed.

The native SDK tests cover an approved caller, a restricted token, another local
user, a forged node, changed child registration, a competing listener, wrong
server identity, malformed greeting and cancellation. Interactive UAC, service
installation, lock/unlock and session transitions still require a Windows desktop.

## References and build inputs

I checked Microsoft's [pipe access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights),
[pipe impersonation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
and [local-only pipe mode](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea).
The GUI adopts a verified native handle through QLocalSocket. I inspected Qt
5.15's official qlocalsocket_win.cpp for handle ownership and descriptor adoption;
I have not imported that source or changed the Qt dependency.

The SDK harness uses Windows runner tools without new third-party libraries.
For local compile checks I extracted Ubuntu's signed-index MinGW packages
(GCC 13.2.0, mingw-w64 11.0.1, binutils 2.41 snapshot). I inspected the package
control scripts and licence notices; no installation hooks were executed and
none of those toolchain files is distributed with the project. These checks
cannot certify a compiler or its entire source as free of vulnerabilities.
