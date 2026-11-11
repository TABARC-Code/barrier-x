/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "../../lib/io/WinPrivateFile.h"
#include "../../lib/io/LogStore.h"
#include "../../lib/ipc/WinLocalPipe.h"
#include <aclapi.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <lm.h>
#include <bcrypt.h>
#include <io.h>
#include <iostream>
#include <stdexcept>
#include <system_error>
#include <vector>
#include <functional>
using barrier::localipc::Handle;
namespace {
void require(bool condition, const char* message) {
    if (!condition) { throw std::runtime_error(message); }
}
struct Descriptor {
    int value;
    explicit Descriptor(int fd) : value(fd) {}
    ~Descriptor() { if (value >= 0) { _close(value); } }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
};
struct Security {
    PSECURITY_DESCRIPTOR value = nullptr;
    ~Security() { LocalFree(value); }
};
struct Impersonation {
    explicit Impersonation(HANDLE token) { require(ImpersonateLoggedOnUser(token), "test impersonation"); }
    ~Impersonation() { if (!RevertToSelf()) { std::terminate(); } }
    Impersonation(const Impersonation&) = delete;
};
struct ScHandle {
    SC_HANDLE value;
    explicit ScHandle(SC_HANDLE handle) : value(handle) {}
    ~ScHandle() { if (value) { CloseServiceHandle(value); } }
    ScHandle(const ScHandle&) = delete;
    ScHandle& operator=(const ScHandle&) = delete;
};
std::vector<BYTE> user(HANDLE token) {
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    require(size != 0, "token size");
    std::vector<BYTE> bytes(size);
    require(GetTokenInformation(token, TokenUser, bytes.data(), size, &size), "token user");
    return bytes;
}
PSID sid(std::vector<BYTE>& bytes) { return reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid; }
void write_identity(const std::wstring& path) {
    Descriptor file(barrier::create_private_file(path));
    require(_write(file.value, "test identity", 13) == 13, "write dummy identity");
}
void read_identity(const std::wstring& path) {
    Descriptor file(barrier::read_private_file(path));
    char bytes[14]{};
    require(_read(file.value, bytes, sizeof(bytes)) == 13 && std::string(bytes, 13) == "test identity", "identity bytes changed");
}
void ownership_refused(const std::wstring& path) {
    bool refused = false;
    try { read_identity(path); }
    catch (const std::runtime_error& error) { refused = std::string(error.what()).find("another owner") != std::string::npos; }
    require(refused, "service accepted foreign ownership");
}
void rejected(const std::function<void()>& operation) {
    bool refused = false;
    try { operation(); } catch (const std::exception&) { refused = true; }
    require(refused, "service accepted an unsafe log operation");
}
std::string read_log(const std::wstring& path) {
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
    require(static_cast<bool>(file), "read dummy log");
    LARGE_INTEGER size{};
    require(GetFileSizeEx(file.get(), &size) && size.QuadPart >= 0 && size.QuadPart <= 4096, "dummy log size");
    std::string bytes(static_cast<std::size_t>(size.QuadPart), '\0'); DWORD count = 0;
    require(ReadFile(file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) && count == bytes.size(), "dummy log bytes");
    return bytes;
}
std::wstring log_security(const std::wstring& path) {
    Security descriptor;
    require(GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr, &descriptor.value) == ERROR_SUCCESS, "log security");
    wchar_t* raw = nullptr;
    require(ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor.value, SDDL_REVISION_1,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &raw, nullptr), "log security text");
    const std::wstring text(raw); LocalFree(raw); return text;
}
constexpr std::time_t log_time = 1700000000;
void refused_log_operations(const std::wstring& filename) {
    const barrier::fs::path path(filename);
    const auto before = read_log(filename);
    const auto security = log_security(filename);
    rejected([&] { barrier::clear_logs(path); });
    rejected([&] { barrier::expire_logs(path, 5, log_time + 6*86400); });
    rejected([&] { barrier::append_log(path, "must not append", 0, log_time); });
    require(read_log(filename) == before && log_security(filename) == security, "refusal changed log contents or permissions");
}
struct TcbDisabled {
    Handle token;
    TOKEN_PRIVILEGES previous{};
    bool changed = false;
    TcbDisabled() {
        HANDLE raw = nullptr;
        require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &raw), "privilege token");
        token.reset(raw);
        TOKEN_PRIVILEGES update{};
        update.PrivilegeCount = 1;
        require(LookupPrivilegeValueW(nullptr, L"SeTcbPrivilege", &update.Privileges[0].Luid), "TCB privilege lookup");
        DWORD size = sizeof(previous);
        SetLastError(ERROR_SUCCESS);
        BOOL result = AdjustTokenPrivileges(token.get(), FALSE, &update, sizeof(previous), &previous, &size);
        require(result && GetLastError() == ERROR_SUCCESS, "disable TCB privilege");
        changed = true;
    }
    ~TcbDisabled() {
        if (changed) {
            SetLastError(ERROR_SUCCESS);
            if (!AdjustTokenPrivileges(token.get(), FALSE, &previous, 0, nullptr, nullptr) || GetLastError() != ERROR_SUCCESS) { std::terminate(); }
        }
    }
};

// FUTURE(BX-004): exercise logout and user switching through the installed desktop service.
// Only dummy identities live in this temporary directory. The service result
// travels through SCM status, rather than another file for somebody to replace.
std::wstring service_name, directory;
constexpr DWORD result_marker = 0x42580000;
constexpr DWORD own_pass = 1, console_pass = 2, foreign_pass = 4, token_failure_pass = 8,
                permission_pass = 16, console_accepted = 32, log_pass = 64, failure = 0x8000;
DWORD stage = 0;
DWORD exercise_service() {
    stage = 1;
    HANDLE raw = nullptr;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw), "service process token");
    Handle token(raw);
    auto process_user = user(token.get());
    BYTE system[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(system);
    require(CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &size) && EqualSid(sid(process_user), system), "service is not LocalSystem");
    DWORD result = result_marker;
    write_identity(directory + L"\\system.pem");
    barrier::replace_private_file(directory + L"\\system.pem", "test identity");
    read_identity(directory + L"\\system.pem");
    result |= own_pass;

    stage = 2;
    Security security; PSID owner = nullptr;
    require(GetNamedSecurityInfoW(const_cast<wchar_t*>((directory + L"\\console.pem").c_str()), SE_FILE_OBJECT,
                                 OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr, &security.value) == ERROR_SUCCESS, "console file owner");
    bool matches_console = false;
    HANDLE console_raw = nullptr;
    if (WTSQueryUserToken(WTSGetActiveConsoleSessionId(), &console_raw)) {
        Handle console(console_raw);
        auto console_user = user(console.get());
        matches_console = EqualSid(owner, sid(console_user)) != FALSE;
    }
    if (matches_console) {
        read_identity(directory + L"\\console.pem");
        if (!EqualSid(owner, system)) {
            bool refused = false;
            try { barrier::replace_private_file(directory + L"\\console.pem", "replacement"); }
            catch (const std::runtime_error&) { refused = true; }
            require(refused, "service replaced a console-owned file");
            read_identity(directory + L"\\console.pem");
        }
        result |= console_accepted;
    }
    else { ownership_refused(directory + L"\\console.pem"); }
    result |= console_pass;

    stage = 3;
    // I prove the service can open the fixture before testing its owner policy.
    { Handle file(CreateFileW((directory + L"\\foreign.pem").c_str(), GENERIC_READ | READ_CONTROL | WRITE_DAC,
                              0, nullptr, OPEN_EXISTING, 0, nullptr));
      require(static_cast<bool>(file), "foreign fixture inaccessible to service"); }
    ownership_refused(directory + L"\\foreign.pem");
    result |= foreign_pass;

    stage = 4;
    { TcbDisabled disabled;
      HANDLE unexpected = nullptr;
      BOOL queried = WTSQueryUserToken(WTSGetActiveConsoleSessionId(), &unexpected);
      Handle cleanup(unexpected);
      require(!queried, "console query succeeded without TCB privilege");
      ownership_refused(directory + L"\\console.pem"); }
    result |= token_failure_pass;

    stage = 5;
    write_identity(directory + L"\\denied.pem");
    Security denied;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(D;;WD;;;OW)(A;;FA;;;SY)", SDDL_REVISION_1, &denied.value, nullptr), "denial ACL");
    PACL acl = nullptr; BOOL present = FALSE, defaulted = FALSE;
    require(GetSecurityDescriptorDacl(denied.value, &present, &acl, &defaulted), "denial DACL");
    require(SetNamedSecurityInfoW(const_cast<wchar_t*>((directory + L"\\denied.pem").c_str()), SE_FILE_OBJECT,
                                 DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr) == ERROR_SUCCESS, "apply denial ACL");
    bool refused = false;
    try { read_identity(directory + L"\\denied.pem"); }
    catch (const std::system_error& error) { refused = error.code().value() == ERROR_ACCESS_DENIED; }
    require(refused, "service ignored denied WRITE_DAC");
    { Handle file(CreateFileW((directory + L"\\denied.pem").c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr));
      char bytes[14]{}; DWORD count = 0;
      require(file && ReadFile(file.get(), bytes, sizeof(bytes), &count, nullptr) && count == 13 &&
              std::string(bytes, 13) == "test identity", "failed migration changed bytes"); }
    result |= permission_pass;

    stage = 6;
    const barrier::fs::path log(directory + L"\\system.log"), backup(directory + L"\\system.log.1");
    barrier::append_log(log, "old service entry", 0, log_time);
    barrier::append_log(backup, "old archive", 0, log_time);
    require(barrier::expire_logs(log, 5, log_time + 5*86400) == 2, "service retention boundary");
    require(read_log(log.native()).empty() && read_log(backup.native()).empty(), "service logs retained contents");
    barrier::append_log(log, "fresh service entry", 5, log_time + 5*86400);
    require(read_log(log.native()).find("fresh service entry") != std::string::npos, "service logging didn't resume");
    require(barrier::clear_logs(log) == 1 && read_log(log.native()).empty(), "manual service log deletion");
    barrier::append_log(log, "after manual deletion", 0, log_time);
    read_identity(directory + L"\\system.pem");

    stage = 7;
    const barrier::fs::path console_log(directory + L"\\console.log");
    if (matches_console) {
        const auto before = log_security(console_log.native());
        require(barrier::clear_logs(console_log) == 1 && read_log(console_log.native()).empty(), "console log deletion");
        barrier::append_log(console_log, "console logging resumed", 0, log_time);
        require(log_security(console_log.native()) == before, "console log ownership or ACL changed");
    } else { refused_log_operations(console_log.native()); }

    stage = 8;
    // I give the service access to this fixture; ownership must still get the final say.
    refused_log_operations(directory + L"\\foreign.log");

    stage = 9;
    { TcbDisabled disabled; refused_log_operations(console_log.native()); }

    stage = 10;
    const barrier::fs::path denied_log(directory + L"\\denied.log");
    barrier::append_log(denied_log, "preserve denied entry", 0, log_time);
    Security denied_write;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(D;;0x2;;;SY)(A;;FA;;;SY)", SDDL_REVISION_1,
        &denied_write.value, nullptr), "denied log ACL");
    acl = nullptr; present = FALSE; defaulted = FALSE;
    require(GetSecurityDescriptorDacl(denied_write.value, &present, &acl, &defaulted), "denied log DACL");
    require(SetNamedSecurityInfoW(const_cast<wchar_t*>(denied_log.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr) == ERROR_SUCCESS, "apply denied log ACL");
    {
        Handle writable(CreateFileW(denied_log.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
        require(!writable && GetLastError() == ERROR_ACCESS_DENIED, "denied log fixture still permits writing");
    }
    refused_log_operations(denied_log.native());

    stage = 11;
    const auto active_before = read_log(log.native()), backup_before = read_log(backup.native());
    for (const auto& path : {log, backup}) {
        Handle held(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
        require(static_cast<bool>(held), "hold service log");
        rejected([&] { barrier::clear_logs(log); });
        rejected([&] { barrier::expire_logs(log, 5, log_time + 6*86400); });
    }
    require(read_log(log.native()) == active_before && read_log(backup.native()) == backup_before, "busy service log changed");
    return result | log_pass;
}
void WINAPI control(DWORD operation) {
    // This is a short-lived test service; cancellation must not leave it running.
    if (operation == SERVICE_CONTROL_STOP) { ExitProcess(ERROR_CANCELLED); }
}
void WINAPI service_main(DWORD, wchar_t**) {
    SERVICE_STATUS_HANDLE handle = RegisterServiceCtrlHandlerW(service_name.c_str(), control);
    if (!handle) { return; }
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    if (!SetServiceStatus(handle, &status)) { return; }
    DWORD result = result_marker | failure;
    try { result = exercise_service(); } catch (...) { result |= stage << 8; }
    status.dwCurrentState = SERVICE_STOPPED;
    status.dwControlsAccepted = 0;
    // SCM preserves the bounded test result as a service-specific exit code.
    status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
    status.dwServiceSpecificExitCode = result;
    SetServiceStatus(handle, &status);
}
struct Account {
    std::wstring name = L"BXSvc" + std::to_wstring(GetCurrentProcessId()) + std::to_wstring(GetTickCount64() % 1000000);
    bool created = false;
    Handle token;
    Account() {
        UCHAR random[24];
        require(BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0, "account randomness");
        std::wstring password = L"Bx9!";
        for (auto byte : random) { password += L"0123456789abcdef"[byte >> 4]; password += L"0123456789abcdef"[byte & 15]; }
        USER_INFO_1 info{};
        info.usri1_name = const_cast<wchar_t*>(name.c_str()); info.usri1_password = const_cast<wchar_t*>(password.c_str());
        info.usri1_priv = USER_PRIV_USER; info.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT;
        DWORD parameter = 0;
        require(NetUserAdd(nullptr, 1, reinterpret_cast<BYTE*>(&info), &parameter) == NERR_Success, "create test user");
        created = true;
        HANDLE raw = nullptr;
        if (!LogonUserW(name.c_str(), L".", password.c_str(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &raw)) {
            NetUserDel(nullptr, name.c_str()); created = false;
            throw std::runtime_error("test user logon");
        }
        token.reset(raw);
    }
    ~Account() { if (created) { NetUserDel(nullptr, name.c_str()); } }
    void remove() {
        token.reset();
        require(NetUserDel(nullptr, name.c_str()) == NERR_Success, "delete test user"); created = false;
    }
};
struct Fixture {
    static void restrict(const std::wstring& target, const std::wstring& owner_path, bool children = false) {
        Security owner_descriptor; PSID owner = nullptr;
        require(GetNamedSecurityInfoW(const_cast<wchar_t*>(owner_path.c_str()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                                     &owner, nullptr, nullptr, nullptr, &owner_descriptor.value) == ERROR_SUCCESS, "fixture owner");
        wchar_t* text = nullptr;
        require(ConvertSidToStringSidW(owner, &text), "fixture owner SID");
        const std::wstring flags = children ? L"OICI" : L"";
        std::wstring acl_text = L"D:P(A;" + flags + L";FA;;;" + std::wstring(text) +
                                 L")(A;" + flags + L";FA;;;SY)";
        LocalFree(text);
        Security security;
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(acl_text.c_str(), SDDL_REVISION_1, &security.value, nullptr), "private fixture ACL");
        PACL acl = nullptr; BOOL present = FALSE, defaulted = FALSE;
        require(GetSecurityDescriptorDacl(security.value, &present, &acl, &defaulted), "fixture DACL");
        require(SetNamedSecurityInfoW(const_cast<wchar_t*>(target.c_str()), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr) == ERROR_SUCCESS, "restrict fixture access");
    }
    Fixture() {
        wchar_t path[MAX_PATH]; DWORD length = GetTempPathW(MAX_PATH, path);
        require(length && length < MAX_PATH, "temporary path");
        directory = std::wstring(path) + L"BXServiceFile-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
        require(CreateDirectoryW(directory.c_str(), nullptr), "fixture directory");
        restrict(directory, directory, true);
    }
    void unlock() {
        Security security;
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;WD)", SDDL_REVISION_1, &security.value, nullptr), "fixture ACL");
        PACL acl = nullptr; BOOL present = FALSE, defaulted = FALSE;
        require(GetSecurityDescriptorDacl(security.value, &present, &acl, &defaulted), "public fixture DACL");
        require(SetNamedSecurityInfoW(const_cast<wchar_t*>(directory.c_str()), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr) == ERROR_SUCCESS,
            "open fixture setup access");
    }
    void lock() {
        // I preserve explicit service access before removing the inherited public ACEs.
        restrict(directory + L"\\foreign.pem", directory + L"\\foreign.pem");
        restrict(directory + L"\\foreign.log", directory + L"\\foreign.log");
        // I close the public setup window before launching anything as LocalSystem.
        restrict(directory, directory + L"\\console.pem", true);
    }
    ~Fixture() {
        for (auto name : {L"console.pem", L"foreign.pem", L"system.pem", L"denied.pem",
                          L"console.log", L"foreign.log", L"system.log", L"system.log.1", L"denied.log"}) {
            DeleteFileW((directory + L"\\" + name).c_str());
        }
        RemoveDirectoryW(directory.c_str());
    }
};
struct TemporaryService {
    ScHandle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)};
    ScHandle handle{nullptr};
    bool marked = false;
    TemporaryService() {
        require(manager.value != nullptr, "open service manager");
        std::vector<wchar_t> path(32768);
        DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        require(length && length < path.size(), "test executable path");
        service_name = L"BXFileTest-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
        std::wstring command = L"\"" + std::wstring(path.data(), length) + L"\" --service \"" + service_name + L"\" \"" + directory + L"\"";
        handle.value = CreateServiceW(manager.value, service_name.c_str(), service_name.c_str(),
            SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL, command.c_str(), nullptr, nullptr, nullptr, L"LocalSystem", nullptr);
        require(handle.value != nullptr, "create temporary service");
    }
    ~TemporaryService() {
        if (handle.value) {
            SERVICE_STATUS status{};
            ControlService(handle.value, SERVICE_CONTROL_STOP, &status);
            if (!marked) { DeleteService(handle.value); }
        }
    }
    void remove() {
        CloseServiceHandle(handle.value); handle.value = nullptr;
        ULONGLONG deadline = GetTickCount64() + 5000;
        do {
            SC_HANDLE probe = OpenServiceW(manager.value, service_name.c_str(), SERVICE_QUERY_STATUS);
            DWORD error = GetLastError();
            if (probe) { CloseServiceHandle(probe); }
            else if (error == ERROR_SERVICE_DOES_NOT_EXIST) { return; }
            Sleep(50);
        } while (GetTickCount64() < deadline);
        throw std::runtime_error("temporary service registration remains");
    }
    DWORD run() {
        require(StartServiceW(handle.value, 0, nullptr), "start temporary service");
        // Mark only after starting: SCM refuses to start an entry already marked for deletion.
        require(DeleteService(handle.value), "mark temporary service for deletion");
        marked = true;
        SERVICE_STATUS_PROCESS status{}; DWORD size = 0;
        ULONGLONG deadline = GetTickCount64() + 20000;
        do {
            require(QueryServiceStatusEx(handle.value, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&status), sizeof(status), &size), "query service result");
            if (status.dwCurrentState == SERVICE_STOPPED) {
                require(status.dwWin32ExitCode == ERROR_SERVICE_SPECIFIC_ERROR, "service stopped without a test result");
                return status.dwServiceSpecificExitCode;
            }
            Sleep(50);
        } while (GetTickCount64() < deadline);
        throw std::runtime_error("service test timed out");
    }
};
}
int wmain(int argc, wchar_t** argv) {
    if (argc == 4 && std::wstring(argv[1]) == L"--service") {
        service_name = argv[2]; directory = argv[3];
        SERVICE_TABLE_ENTRYW table[] = {{const_cast<wchar_t*>(service_name.c_str()), service_main}, {nullptr, nullptr}};
        return StartServiceCtrlDispatcherW(table) ? 0 : 1;
    }
    try {
        Fixture fixture;
        write_identity(directory + L"\\console.pem");
        barrier::append_log(barrier::fs::path(directory + L"\\console.log"), "dummy console entry", 0, log_time);
        fixture.unlock();
        Account account;
        {
            Impersonation caller(account.token.get());
            Handle foreign(CreateFileW((directory + L"\\foreign.pem").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, 0, nullptr));
            require(static_cast<bool>(foreign), "foreign identity fixture");
            Handle foreign_log(CreateFileW((directory + L"\\foreign.log").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, 0, nullptr));
            const std::string bytes = "# barrier-x log 1 1700000000\ndummy foreign entry\n"; DWORD count = 0;
            require(foreign_log && WriteFile(foreign_log.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) &&
                    count == bytes.size(), "foreign log fixture");
        }
        fixture.lock();
        DWORD result = 0;
        { TemporaryService service; result = service.run(); service.remove(); }
        account.remove();
        constexpr DWORD required = result_marker | own_pass | console_pass | foreign_pass | token_failure_pass | permission_pass | log_pass;
        if ((result & ~console_accepted) != required) {
            throw std::runtime_error("LocalSystem file check failed at stage " + std::to_string((result >> 8) & 0x7f));
        }
        {
            Handle denied(CreateFileW((directory + L"\\system.log").c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
            require(!denied && GetLastError() == ERROR_ACCESS_DENIED, "ordinary process read a service-owned log");
        }
        std::cout << "PASS LocalSystem key creation and reading\n";
        if (result & console_accepted) { std::cout << "PASS active console user's key\n"; }
        else { std::cout << "SKIP console-user acceptance: runner has no matching active console\nPASS console-owner mismatch refused\n"; }
        std::cout << "PASS foreign owner's key refused\nPASS failed console-token lookup refused\nPASS denied permission migration preserves bytes\n";
        std::cout << "PASS service log retention, deletion and resumed writing\n";
        if (result & console_accepted) { std::cout << "PASS active console user's log deletion preserves ownership\n"; }
        else { std::cout << "SKIP console log acceptance: runner has no matching active console\nPASS console log owner mismatch refused\n"; }
        std::cout << "PASS foreign log owner refused\nPASS failed console-token log access refused\n"
                     "PASS denied log writes preserve contents and ACL\nPASS busy service logs preserved\n"
                     "PASS ordinary process cannot read service-owned logs\n";
        return 0;
    }
    catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
