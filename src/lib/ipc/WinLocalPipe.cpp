/*
 * Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE.
 */
#include "WinLocalPipe.h"
#ifdef _WIN32
#include <sddl.h>
#include <wtsapi32.h>
#include <vector>
#include <stdexcept>
#include <cstring>

namespace barrier { namespace localipc {
namespace {
[[noreturn]] void failure() { throw std::runtime_error("local service access failed"); }
std::vector<unsigned char> information(HANDLE token, TOKEN_INFORMATION_CLASS kind)
{
    DWORD size = 0;
    GetTokenInformation(token, kind, nullptr, 0, &size);
    if (!size || GetLastError() != ERROR_INSUFFICIENT_BUFFER) { failure(); }
    std::vector<unsigned char> result(size);
    if (!GetTokenInformation(token, kind, result.data(), size, &size)) { failure(); }
    return result;
}
bool administrator(HANDLE token)
{
    unsigned char sid[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(sid);
    BOOL member = FALSE;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sid, &size) ||
        !CheckTokenMembership(token, sid, &member)) { return false; }
    return member && !IsTokenRestricted(token);
}
DWORD session(HANDLE token)
{
    const auto data = information(token, TokenSessionId);
    return *reinterpret_cast<const DWORD*>(data.data());
}
PSID logonSid(std::vector<unsigned char>& data)
{
    auto* groups = reinterpret_cast<TOKEN_GROUPS*>(data.data());
    for (DWORD i = 0; i < groups->GroupCount; ++i) {
        if ((groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) {
            return groups->Groups[i].Sid;
        }
    }
    return nullptr;
}
Handle caller(HANDLE pipe)
{
    if (!ImpersonateNamedPipeClient(pipe)) { failure(); }
    HANDLE raw = nullptr;
    const BOOL opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw);
    // I cannot continue a privileged service with an unknown thread identity.
    if (!RevertToSelf()) { TerminateProcess(GetCurrentProcess(), ERROR_ACCESS_DENIED); std::terminate(); }
    Handle token(raw);
    if (!opened) { failure(); }
    auto level = information(token.get(), TokenImpersonationLevel);
    if (*reinterpret_cast<SECURITY_IMPERSONATION_LEVEL*>(level.data()) < SecurityIdentification) { failure(); }
    return token;
}
bool await(HANDLE pipe, OVERLAPPED& operation, HANDLE stop, DWORD timeout, DWORD& count)
{
    HANDLE handles[] = {operation.hEvent, stop};
    const DWORD waited = WaitForMultipleObjects(stop ? 2 : 1, handles, FALSE, timeout);
    if (waited == WAIT_OBJECT_0 && GetOverlappedResult(pipe, &operation, &count, FALSE)) { return true; }
    CancelIoEx(pipe, &operation);
    GetOverlappedResult(pipe, &operation, &count, TRUE);
    return false;
}
}
DWORD transfer(HANDLE pipe, void* data, DWORD size, bool writing, HANDLE stop, DWORD timeout)
{
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) { failure(); }
    OVERLAPPED operation{};
    operation.hEvent = event.get();
    DWORD count = 0;
    BOOL ok = writing ? WriteFile(pipe, data, size, nullptr, &operation) :
                        ReadFile(pipe, data, size, nullptr, &operation);
    if (ok) {
        if (!GetOverlappedResult(pipe, &operation, &count, FALSE)) { failure(); }
    }
    else if (GetLastError() != ERROR_IO_PENDING ||
             !await(pipe, operation, stop, timeout, count)) { failure(); }
    return count;
}
Handle connect(const std::wstring& name, DWORD expectedServer)
{
    if (!expectedServer) { failure(); }
    // I request data rights only. GENERIC_WRITE also permits pipe instances.
    Handle pipe(CreateFileW(name.c_str(), FILE_READ_DATA | FILE_WRITE_DATA |
                            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                            0, nullptr, OPEN_EXISTING,
                            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                            nullptr));
    ULONG server = 0;
    if (!pipe || !GetNamedPipeServerProcessId(pipe.get(), &server) || server != expectedServer) { failure(); }
    return pipe;
}
Handle connectService(bool wait)
{
    struct ServiceHandle {
        SC_HANDLE value;
        ~ServiceHandle() { if (value) { CloseServiceHandle(value); } }
    };
    ServiceHandle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    ServiceHandle service{manager.value ? OpenServiceW(manager.value, L"Barrier", SERVICE_QUERY_STATUS) : nullptr};
    SERVICE_STATUS_PROCESS status{};
    DWORD size = 0;
    if (!service.value || !QueryServiceStatusEx(service.value, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<BYTE*>(&status), sizeof(status), &size) ||
        status.dwCurrentState != SERVICE_RUNNING || !status.dwProcessId) { failure(); }
    if (wait && !WaitNamedPipeW(service_pipe, 3000)) { failure(); }
    return connect(service_pipe, status.dwProcessId);
}
bool elevatedAdministrator()
{
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &raw)) { return false; }
    Handle primary(raw), token;
    HANDLE duplicate = nullptr;
    if (!DuplicateToken(primary.get(), SecurityIdentification, &duplicate)) { return false; }
    token.reset(duplicate);
    return administrator(token.get());
}
Policy::Policy(bool service) : service_(service) { }
Handle Policy::sessionToken() const
{
    HANDLE raw = nullptr;
    if (service_) {
        const DWORD active = WTSGetActiveConsoleSessionId();
        if (active == 0xffffffff || !WTSQueryUserToken(active, &raw)) { failure(); }
    }
    else if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) { failure(); }
    return Handle(raw);
}
void Policy::child(HANDLE process)
{
    Handle replacement;
    if (process) {
        HANDLE duplicate = nullptr;
        if (!DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(), &duplicate,
                             PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, 0)) { failure(); }
        replacement.reset(duplicate);
    }
    std::lock_guard<std::mutex> lock(mutex_);
    child_ = std::move(replacement);
}
bool Policy::gui(HANDLE token, bool management) const
{
    try {
        auto active = sessionToken();
        if (session(active.get()) != session(token)) { return false; }
        if (IsTokenRestricted(token) || (management && !administrator(token))) { return false; }
        // I compare the linked logon for UAC split tokens, retaining the original
        // administrator token for the command permission decision above.
        auto linkedIdentity = [](HANDLE source) {
            auto kind = information(source, TokenElevationType);
            if (*reinterpret_cast<TOKEN_ELEVATION_TYPE*>(kind.data()) == TokenElevationTypeFull) {
                auto linked = information(source, TokenLinkedToken);
                return Handle(reinterpret_cast<TOKEN_LINKED_TOKEN*>(linked.data())->LinkedToken);
            }
            return Handle();
        };
        auto expectedLinked = linkedIdentity(active.get());
        auto actualLinked = linkedIdentity(token);
        const HANDLE expectedToken = expectedLinked ? expectedLinked.get() : active.get();
        const HANDLE actualToken = actualLinked ? actualLinked.get() : token;
        auto expectedUser = information(expectedToken, TokenUser);
        auto actualUser = information(actualToken, TokenUser);
        auto expectedGroups = information(expectedToken, TokenGroups);
        auto actualGroups = information(actualToken, TokenGroups);
        auto* expected = logonSid(expectedGroups);
        auto* actual = logonSid(actualGroups);
        return expected && actual && EqualSid(expected, actual) &&
            EqualSid(reinterpret_cast<TOKEN_USER*>(expectedUser.data())->User.Sid,
                     reinterpret_cast<TOKEN_USER*>(actualUser.data())->User.Sid);
    }
    catch (...) { return false; }
}
bool Policy::node(HANDLE token, DWORD pid) const
{
    try {
        auto active = sessionToken();
        if (session(active.get()) != session(token)) { return false; }
        std::lock_guard<std::mutex> lock(mutex_);
        return child_ && GetProcessId(child_.get()) == pid &&
               WaitForSingleObject(child_.get(), 0) == WAIT_TIMEOUT;
    }
    catch (...) { return false; }
}
bool Peer::allows(Operation operation) const
{
    if (!connected.load() || !token || !policy || !process ||
        WaitForSingleObject(process.get(), 0) != WAIT_TIMEOUT) { return false; }
    if (role == Role::Node) {
        return (operation == Operation::Hello || operation == Operation::Shutdown) &&
               policy->node(token.get(), pid);
    }
    return operation != Operation::Shutdown &&
           policy->gui(token.get(), operation == Operation::Command);
}
Listener::Listener(std::wstring name, std::shared_ptr<Policy> policy) :
    name_(std::move(name)), policy_(std::move(policy)), next_(instance(true)) { }
Handle Listener::instance(bool first)
{
    PSECURITY_DESCRIPTOR raw = nullptr;
    // Interactive callers can exchange bytes, but cannot create server instances.
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0012019b;;;IU)", SDDL_REVISION_1, &raw, nullptr)) { failure(); }
    std::unique_ptr<void, decltype(&LocalFree)> descriptor(raw, LocalFree);
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), raw, FALSE};
    Handle pipe(CreateNamedPipeW(name_.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
        (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0), PIPE_TYPE_BYTE | PIPE_READMODE_BYTE |
        PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 32, 65536, 65536, 0, &attributes));
    if (!pipe) { failure(); }
    return pipe;
}
Accepted Listener::accept(HANDLE stop)
{
    Accepted result;
    result.pipe = std::move(next_);
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!result.pipe || !event) { failure(); }
    OVERLAPPED operation{};
    operation.hEvent = event.get();
    DWORD ignored = 0;
    if (!ConnectNamedPipe(result.pipe.get(), &operation)) {
        const auto error = GetLastError();
        if (error != ERROR_PIPE_CONNECTED &&
            (error != ERROR_IO_PENDING || !await(result.pipe.get(), operation, stop, INFINITE, ignored))) { return Accepted(); }
    }
    // I retain a listening instance before examining an untrusted greeting.
    try { next_ = instance(false); }
    catch (...) {
        DisconnectNamedPipe(result.pipe.get());
        next_ = std::move(result.pipe);
        throw;
    }
    const ULONGLONG deadline = GetTickCount64() + 3000;
    DWORD offset = 0;
    while (offset < result.greeting.size()) {
        const auto now = GetTickCount64();
        if (now >= deadline) { failure(); }
        DWORD count = transfer(result.pipe.get(), result.greeting.data() + offset,
                               DWORD(result.greeting.size()) - offset, false, stop, DWORD(deadline - now));
        if (!count) { failure(); }
        offset += count;
    }
    if (std::memcmp(result.greeting.data(), "IHEL", 4) ||
        (result.greeting[4] != 1 && result.greeting[4] != 2)) { failure(); }
    auto peer = std::make_shared<Peer>();
    peer->token = caller(result.pipe.get());
    ULONG pid = 0;
    if (!GetNamedPipeClientProcessId(result.pipe.get(), &pid)) { failure(); }
    peer->pid = pid;
    peer->process.reset(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid));
    if (!peer->process) { failure(); }
    peer->role = static_cast<Role>(result.greeting[4]);
    peer->policy = policy_;
    if (!peer->allows(Operation::Hello) || !policy_->acquire()) { failure(); }
    peer->leased = true;
    result.peer = std::move(peer);
    return result;
}
} }
#endif
