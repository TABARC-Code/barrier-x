/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "WinPrivateFile.h"
#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <wtsapi32.h>
#include <io.h>
#include <fcntl.h>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <vector>
#include <atomic>
#include <cstring>

namespace barrier {
namespace {
struct Handle {
    HANDLE value;
    explicit Handle(HANDLE h) : value(h) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) { CloseHandle(value); } }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
struct LocalFreeDeleter { void operator()(void* p) const { LocalFree(p); } };
using Local = std::unique_ptr<void, LocalFreeDeleter>;
void fail(DWORD error, const char* operation) {
    throw std::system_error(static_cast<int>(error), std::system_category(), operation);
}
void check(BOOL result, const char* operation) { if (!result) { fail(GetLastError(), operation); } }
std::vector<BYTE> token_user(HANDLE token) {
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (!size) { fail(GetLastError(), "Could not size identity owner"); }
    std::vector<BYTE> user(size);
    check(GetTokenInformation(token, TokenUser, user.data(), size, &size), "Could not read identity owner");
    return user;
}
PSID sid(std::vector<BYTE>& user) { return reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid; }
std::vector<BYTE> process_user() {
    HANDLE raw = nullptr;
    check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw), "Could not open identity owner token");
    Handle token(raw);
    return token_user(token.value);
}
std::vector<BYTE> system_sid() {
    DWORD size = SECURITY_MAX_SID_SIZE;
    std::vector<BYTE> result(size);
    check(CreateWellKnownSid(WinLocalSystemSid, nullptr, result.data(), &size), "Could not identify LocalSystem");
    return result;
}
std::vector<BYTE> private_acl(PSID owner, PSID system) {
    DWORD size = sizeof(ACL) + 2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) +
                 GetLengthSid(owner) + GetLengthSid(system);
    std::vector<BYTE> result(size);
    PACL acl = reinterpret_cast<PACL>(result.data());
    check(InitializeAcl(acl, size, ACL_REVISION), "Could not initialise identity ACL");
    check(AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, owner), "Could not grant identity owner access");
    if (!EqualSid(owner, system)) {
        check(AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, system), "Could not grant service identity access");
    }
    return result;
}
void check_path(const std::wstring& path) {
    // I reject alternate streams: a private identity is a file, not a hiding place.
    auto colon = path.find(L':');
    const std::size_t drive = path.compare(0, 4, L"\\\\?\\") == 0 ? 4 : 0;
    bool drive_letter = path.size() > drive && ((path[drive] >= L'A' && path[drive] <= L'Z') ||
                                               (path[drive] >= L'a' && path[drive] <= L'z'));
    if (path.find(L'\0') != std::wstring::npos ||
        (colon != std::wstring::npos && (!drive_letter || colon != drive + 1 || path.find(L':', colon + 1) != std::wstring::npos))) {
        throw std::runtime_error("Identity streams are unsupported");
    }
}
void check_file(HANDLE file, DWORD maximum = 1024 * 1024) {
    BY_HANDLE_FILE_INFORMATION info{};
    check(GetFileInformationByHandle(file, &info), "Could not inspect identity file");
    if (GetFileType(file) != FILE_TYPE_DISK ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
        info.nNumberOfLinks != 1 || info.nFileSizeHigh || info.nFileSizeLow > maximum) {
        throw std::runtime_error("Identity must be a regular file with one link, at most 1 MiB");
    }
}
void verify_acl(HANDLE file, PSID expected, PSID system) {
    PSID owner = nullptr;
    PACL acl = nullptr;
    PSECURITY_DESCRIPTOR raw = nullptr;
    DWORD error = GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                 &owner, nullptr, &acl, nullptr, &raw);
    Local descriptor(raw);
    if (error) { fail(error, "Could not verify identity ACL"); }
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    check(GetSecurityDescriptorControl(raw, &control, &revision), "Could not inspect identity ACL control");
    bool owner_seen = false, system_seen = false;
    if (!owner || !EqualSid(owner, expected) || !acl || !IsValidAcl(acl) || !(control & SE_DACL_PROTECTED)) {
        throw std::runtime_error("Identity permissions remain unsafe");
    }
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        void* entry = nullptr;
        check(GetAce(acl, i, &entry), "Could not inspect identity ACL entry");
        auto ace = static_cast<ACCESS_ALLOWED_ACE*>(entry);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceFlags || ace->Mask != FILE_ALL_ACCESS) {
            throw std::runtime_error("Identity ACL contains unexpected rights");
        }
        PSID principal = &ace->SidStart;
        if (EqualSid(principal, expected)) { owner_seen = true; }
        else if (!EqualSid(principal, system)) { throw std::runtime_error("Identity ACL contains another principal"); }
        if (EqualSid(principal, system)) { system_seen = true; }
    }
    if (!owner_seen || !system_seen) { throw std::runtime_error("Identity ACL lacks required access"); }
}
int descriptor(Handle& file, int flags) {
    int result = _open_osfhandle(reinterpret_cast<intptr_t>(file.value), flags | _O_BINARY | _O_NOINHERIT);
    if (result == -1) { throw std::runtime_error("Could not open checked identity stream"); }
    file.value = INVALID_HANDLE_VALUE;
    return result;
}
}

int create_private_file(const std::wstring& path) {
    check_path(path);
    auto user = process_user();
    auto system = system_sid();
    auto bytes = private_acl(sid(user), system.data());
    SECURITY_DESCRIPTOR security{};
    check(InitializeSecurityDescriptor(&security, SECURITY_DESCRIPTOR_REVISION), "Could not initialise identity security");
    check(SetSecurityDescriptorOwner(&security, sid(user), FALSE), "Could not set identity owner");
    check(SetSecurityDescriptorDacl(&security, TRUE, reinterpret_cast<PACL>(bytes.data()), FALSE), "Could not set identity ACL");
    check(SetSecurityDescriptorControl(&security, SE_DACL_PROTECTED, SE_DACL_PROTECTED), "Could not protect identity ACL");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), &security, FALSE};
    // I supply the ACL at creation; closing the door after writing the key is late.
    Handle file(CreateFileW(path.c_str(), GENERIC_WRITE | READ_CONTROL | DELETE, 0, &attributes, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) { fail(GetLastError(), "Could not create private identity file"); }
    try {
        check_file(file.value);
        verify_acl(file.value, sid(user), system.data());
        return descriptor(file, _O_WRONLY);
    }
    catch (...) {
        FILE_DISPOSITION_INFO disposition{TRUE};
        SetFileInformationByHandle(file.value, FileDispositionInfo, &disposition, sizeof(disposition));
        throw;
    }
}

static int open_checked_file(const std::wstring& path, bool log_edit) {
    check_path(path);
    // No write/delete sharing: the checked file stays put until the snapshot is read.
    Handle file(CreateFileW(path.c_str(), GENERIC_READ | READ_CONTROL | (log_edit ? GENERIC_WRITE : WRITE_DAC), 0, nullptr, OPEN_EXISTING,
                            FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) { fail(GetLastError(), "Could not open private identity file"); }
    check_file(file.value, log_edit ? 2 * 1024 * 1024 : 1024 * 1024);
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR raw = nullptr;
    DWORD error = GetSecurityInfo(file.value, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                                 &owner, nullptr, nullptr, nullptr, &raw);
    Local security(raw);
    if (error) { fail(error, "Could not inspect identity ownership"); }
    auto user = process_user();
    auto system = system_sid();
    bool allowed = owner && EqualSid(owner, sid(user));
    if (!allowed && owner && EqualSid(sid(user), system.data())) {
        // The service may read its console user's key, never an arbitrary user's file.
        // FUTURE(BX-007): distinguish an unavailable console token from a foreign owner.
        HANDLE raw_token = nullptr;
        if (WTSQueryUserToken(WTSGetActiveConsoleSessionId(), &raw_token)) {
            Handle token(raw_token);
            auto console = token_user(token.value);
            allowed = EqualSid(owner, sid(console)) != FALSE;
        }
    }
    if (!allowed) { throw std::runtime_error("Identity belongs to another owner; explicit repair is required"); }
    if (!log_edit) {
        auto bytes = private_acl(owner, system.data());
        error = SetSecurityInfo(file.value, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                nullptr, nullptr, reinterpret_cast<PACL>(bytes.data()), nullptr);
        if (error) { fail(error, "Could not restrict identity permissions"); }
    }
    // I don't rewrite a configured log's ACL before recognising its contents.
    verify_acl(file.value, owner, system.data());
    check_file(file.value, log_edit ? 2 * 1024 * 1024 : 1024 * 1024);
    return descriptor(file, log_edit ? _O_RDWR : _O_RDONLY);
}

int read_private_file(const std::wstring& path) { return open_checked_file(path, false); }
int edit_private_log(const std::wstring& path) { return open_checked_file(path, true); }

void replace_private_file(const std::wstring& path, const std::string& bytes) {
    check_path(path);
    if (path.empty() || bytes.size() > 1024 * 1024) {
        throw std::runtime_error("Private file replacement needs a path and at most 1 MiB");
    }
    DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (!needed) { fail(GetLastError(), "Could not resolve private file path"); }
    if (needed > 32768) { throw std::runtime_error("Private file path is too long"); }
    std::vector<wchar_t> full(needed);
    DWORD length = GetFullPathNameW(path.c_str(), needed, full.data(), nullptr);
    if (!length || length >= needed) { throw std::runtime_error("Private file path could not be resolved consistently"); }
    const std::wstring target(full.data(), length);
    check_path(target);
    // I refuse unsafe existing files before making a replacement, not after it.
    try {
        int fd = read_private_file(target);
        struct Reader { int value; ~Reader() { _close(value); } } reader{fd};
        auto user = process_user();
        auto system = system_sid();
        // A service mustn't replace a console user's file with a System-owned one.
        verify_acl(reinterpret_cast<HANDLE>(_get_osfhandle(fd)), sid(user), system.data());
    }
    catch (const std::system_error& error) {
        if (error.code().value() != ERROR_FILE_NOT_FOUND) { throw; }
    }
    std::vector<BYTE> rename_bytes(sizeof(FILE_RENAME_INFO) + target.size() * sizeof(wchar_t), 0);
    auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(rename_bytes.data());
    rename->ReplaceIfExists = TRUE;
    rename->FileNameLength = static_cast<DWORD>(target.size() * sizeof(wchar_t));
    std::memcpy(rename->FileName, target.data(), rename->FileNameLength);

    static std::atomic<unsigned long long> sequence{0};
    int fd = -1;
    for (int attempt = 0; attempt < 64; ++attempt) {
        const auto temporary = target + L".pending-" + std::to_wstring(GetCurrentProcessId()) +
            L"-" + std::to_wstring(sequence.fetch_add(1, std::memory_order_relaxed));
        try { fd = create_private_file(temporary); break; }
        catch (const std::system_error& error) {
            if (error.code() != std::errc::file_exists) { throw; }
        }
    }
    if (fd < 0) { throw std::runtime_error("Could not reserve a private replacement file"); }
    struct Pending {
        int descriptor;
        HANDLE handle;
        bool published = false;
        ~Pending() {
            if (!published) {
                FILE_DISPOSITION_INFO disposition{TRUE};
                SetFileInformationByHandle(handle, FileDispositionInfo, &disposition, sizeof(disposition));
            }
            _close(descriptor);
        }
    } file{fd, reinterpret_cast<HANDLE>(_get_osfhandle(fd))};
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        DWORD written = 0;
        check(WriteFile(file.handle, bytes.data() + offset, static_cast<DWORD>(bytes.size() - offset),
                        &written, nullptr), "Could not write private replacement file");
        if (!written) { throw std::runtime_error("Private replacement write made no progress"); }
        offset += written;
    }
    check(FlushFileBuffers(file.handle), "Could not flush private replacement file");
    check_file(file.handle);
    // 2.4.24: I keep the protected replacement handle open through publication.
    check(SetFileInformationByHandle(file.handle, FileRenameInfo, rename, static_cast<DWORD>(rename_bytes.size())),
          "Could not publish private replacement file");
    file.published = true;
}
}
#endif
