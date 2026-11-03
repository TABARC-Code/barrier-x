/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "../../lib/io/WinPrivateFile.h"
#include "../../lib/ipc/WinLocalPipe.h"
#include <aclapi.h>
#include <sddl.h>
#include <lm.h>
#include <bcrypt.h>
#include <io.h>
#include <iostream>
#include <stdexcept>
#include <functional>
#include <system_error>
#include <vector>
using barrier::localipc::Handle;
void require(bool value, const char* message) { if (!value) { throw std::runtime_error(message); } }
struct Descriptor {
    int value;
    explicit Descriptor(int fd) : value(fd) {}
    ~Descriptor() { if (value >= 0) { _close(value); } }
};
struct Fixture {
    std::wstring directory;
    std::vector<std::wstring> files;
    Fixture() {
        wchar_t temporary[MAX_PATH];
        require(GetTempPathW(MAX_PATH, temporary) != 0, "temporary path");
        directory = std::wstring(temporary) + L"BXFile-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
        PSECURITY_DESCRIPTOR raw = nullptr;
        // Deliberately public test directory: the file must not inherit this ACL.
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OICI;FA;;;WD)", SDDL_REVISION_1, &raw, nullptr), "test directory ACL");
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), raw, FALSE};
        BOOL made = CreateDirectoryW(directory.c_str(), &attributes);
        LocalFree(raw);
        require(made, "create test directory");
    }
    std::wstring path(const wchar_t* name) { files.push_back(directory + L"\\" + name); return files.back(); }
    ~Fixture() { for (auto& file : files) { DeleteFileW(file.c_str()); } RemoveDirectoryW(directory.c_str()); }
};
void public_acl(const std::wstring& path) {
    PSECURITY_DESCRIPTOR raw = nullptr;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;WD)", SDDL_REVISION_1, &raw, nullptr), "test public ACL");
    PACL acl = nullptr; BOOL present = FALSE, defaulted = FALSE;
    require(GetSecurityDescriptorDacl(raw, &present, &acl, &defaulted), "read test ACL");
    DWORD result = SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
    LocalFree(raw);
    require(result == ERROR_SUCCESS, "make test file public");
}
void write_key(const std::wstring& path) {
    Descriptor file(barrier::create_private_file(path));
    require(_write(file.value, "test identity", 13) == 13, "write fixture");
}
void check_private(HANDLE file) {
    PSECURITY_DESCRIPTOR raw = nullptr; PSID owner = nullptr; PACL acl = nullptr;
    DWORD result = GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                   &owner, nullptr, &acl, nullptr, &raw);
    require(result == ERROR_SUCCESS, "query file ACL");
    SECURITY_DESCRIPTOR_CONTROL control = 0; DWORD revision = 0;
    bool valid = GetSecurityDescriptorControl(raw, &control, &revision) && (control & SE_DACL_PROTECTED) && owner && acl;
    BYTE system[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(system);
    valid = valid && CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &size);
    bool own = false, service = false;
    if (valid) {
        for (DWORD i = 0; i < acl->AceCount; ++i) {
            void* raw_ace = nullptr; valid = valid && GetAce(acl, i, &raw_ace);
            if (!valid) { break; }
            auto ace = static_cast<ACCESS_ALLOWED_ACE*>(raw_ace);
            PSID principal = &ace->SidStart;
            valid = valid && ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && !ace->Header.AceFlags && ace->Mask == FILE_ALL_ACCESS &&
                    (EqualSid(principal, owner) || EqualSid(principal, system));
            own = own || EqualSid(principal, owner); service = service || EqualSid(principal, system);
        }
    }
    LocalFree(raw);
    require(valid && own && service, "owner/System protected ACL");
}
void rejected(const std::function<void()>& operation) {
    bool failed = false;
    try { operation(); } catch (const std::exception&) { failed = true; }
    require(failed, "unsafe identity accepted");
}
void creation() {
    Fixture f; auto path = f.path(L"new.pem");
    Descriptor file(barrier::create_private_file(path));
    HANDLE handle = reinterpret_cast<HANDLE>(_get_osfhandle(file.value));
    check_private(handle);
    DWORD flags = 0; require(GetHandleInformation(handle, &flags) && !(flags & HANDLE_FLAG_INHERIT), "inherited key handle");
    require(_write(file.value, "key", 3) == 3, "write private file");
}
void migration() {
    Fixture f; auto path = f.path(L"legacy.pem"); write_key(path); public_acl(path);
    Descriptor file(barrier::read_private_file(path)); check_private(reinterpret_cast<HANDLE>(_get_osfhandle(file.value)));
    char bytes[13]; require(_read(file.value, bytes, sizeof(bytes)) == 13 && std::string(bytes, 13) == "test identity", "migration changed bytes");
}
void collision() {
    Fixture f; auto path = f.path(L"exists.pem"); write_key(path);
    bool exists = false;
    try { Descriptor file(barrier::create_private_file(path)); }
    catch (const std::system_error& error) { exists = error.code() == std::errc::file_exists; }
    require(exists, "collision must be retryable");
    Descriptor file(barrier::read_private_file(path)); char bytes[13]; require(_read(file.value, bytes, 13) == 13, "collision truncated identity");
}
void hardlink() {
    Fixture f; auto path = f.path(L"key.pem"), link = f.path(L"hard.pem"); write_key(path);
    require(CreateHardLinkW(link.c_str(), path.c_str(), nullptr), "hardlink fixture");
    rejected([&] { Descriptor file(barrier::read_private_file(link)); });
}
void symlink() {
    Fixture f; auto path = f.path(L"key.pem"), link = f.path(L"symbolic.pem"); write_key(path);
    require(CreateSymbolicLinkW(link.c_str(), path.c_str(), 2) || CreateSymbolicLinkW(link.c_str(), path.c_str(), 0), "symlink fixture");
    rejected([&] { Descriptor file(barrier::read_private_file(link)); });
    Descriptor file(barrier::read_private_file(path)); check_private(reinterpret_cast<HANDLE>(_get_osfhandle(file.value)));
}
void directory() { Fixture f; rejected([&] { Descriptor file(barrier::read_private_file(f.directory)); }); }
void size_limit() {
    Fixture f; auto path = f.path(L"large.pem");
    { Descriptor file(barrier::create_private_file(path)); require(_chsize_s(file.value, 1024 * 1024 + 1) == 0, "large fixture"); }
    rejected([&] { Descriptor file(barrier::read_private_file(path)); });
}
void sharing() {
    Fixture f; auto path = f.path(L"locked.pem"), moved = f.path(L"moved.pem"); write_key(path);
    Descriptor file(barrier::read_private_file(path));
    require(!MoveFileW(path.c_str(), moved.c_str()), "identity renamed while being read");
    Handle writer(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    require(!writer, "identity modified while being read");
}
void replacement() {
    Fixture f; auto old = f.path(L"old.pem"), fresh = f.path(L"fresh.pem"); write_key(old); public_acl(old); write_key(fresh);
    require(MoveFileExW(fresh.c_str(), old.c_str(), MOVEFILE_REPLACE_EXISTING), "replace identity");
    Handle file(CreateFileW(old.c_str(), READ_CONTROL, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    require(static_cast<bool>(file), "open replaced identity"); check_private(file.get());
}
void streams() {
    Fixture f; auto path = f.path(L"stream.pem"); write_key(path);
    rejected([&] { Descriptor file(barrier::read_private_file(path + L":hidden")); });
    rejected([&] { Descriptor file(barrier::create_private_file(path + L":hidden")); });
}
void permission_failure() {
    Fixture f; auto path = f.path(L"denied.pem"); write_key(path);
    PSECURITY_DESCRIPTOR raw = nullptr;
    // OWNER RIGHTS removes the owner's implicit WRITE_DAC for this failure fixture.
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(D;;WD;;;OW)(A;;FA;;;WD)", SDDL_REVISION_1, &raw, nullptr), "deny fixture ACL");
    PACL acl = nullptr; BOOL present = FALSE, defaulted = FALSE;
    require(GetSecurityDescriptorDacl(raw, &present, &acl, &defaulted), "deny fixture DACL");
    Handle retained(CreateFileW(path.c_str(), WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
    require(static_cast<bool>(retained), "retain ACL repair handle");
    DWORD result = SetSecurityInfo(retained.get(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                   nullptr, nullptr, acl, nullptr);
    require(result == ERROR_SUCCESS, "deny permission changes");
    // Close the retained handle while testing; sharing refusal must not mask the ACL failure.
    retained.reset();
    Handle denied(CreateFileW(path.c_str(), GENERIC_READ | WRITE_DAC, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    require(!denied && GetLastError() == ERROR_ACCESS_DENIED, "deny fixture did not refuse WRITE_DAC");
    rejected([&] { Descriptor file(barrier::read_private_file(path)); });
    Handle reader(CreateFileW(path.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    require(static_cast<bool>(reader), "read denied fixture bytes");
    char bytes[13]; DWORD count = 0;
    require(ReadFile(reader.get(), bytes, sizeof(bytes), &count, nullptr) && count == 13 && std::string(bytes, 13) == "test identity", "failed migration changed bytes");
    LocalFree(raw);
}
void busy_writer() {
    Fixture f; auto path = f.path(L"busy.pem"); write_key(path);
    Handle writer(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
    require(static_cast<bool>(writer), "existing writer fixture");
    rejected([&] { Descriptor file(barrier::read_private_file(path)); });
}
void extended_path() {
    Fixture f; auto path = f.path(L"extended.pem");
    auto extended = std::wstring(L"\\\\?\\") + path;
    { Descriptor file(barrier::create_private_file(extended)); }
    Descriptor file(barrier::read_private_file(extended));
    check_private(reinterpret_cast<HANDLE>(_get_osfhandle(file.value)));
}
struct Impersonation {
    explicit Impersonation(HANDLE token) { require(ImpersonateLoggedOnUser(token), "test impersonation"); }
    ~Impersonation() { if (!RevertToSelf()) { std::terminate(); } }
};
void other_user() {
    Fixture f; auto path = f.path(L"private.pem"), foreign = f.path(L"foreign.pem"); write_key(path);
    struct Account {
        std::wstring name = L"BXFile" + std::to_wstring(GetCurrentProcessId()) + std::to_wstring(GetTickCount64() % 1000000);
        bool created = false;
        ~Account() { if (created) { NetUserDel(nullptr, name.c_str()); } }
    } account;
    UCHAR random[24]; require(BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0, "account randomness");
    std::wstring password = L"Bx9!";
    for (auto value : random) { password += L"0123456789abcdef"[value >> 4]; password += L"0123456789abcdef"[value & 15]; }
    USER_INFO_1 user{}; user.usri1_name = const_cast<wchar_t*>(account.name.c_str());
    user.usri1_password = const_cast<wchar_t*>(password.c_str()); user.usri1_priv = USER_PRIV_USER; user.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT;
    DWORD parameter = 0;
    require(NetUserAdd(nullptr, 1, reinterpret_cast<BYTE*>(&user), &parameter) == NERR_Success, "create test account"); account.created = true;
    HANDLE raw = nullptr;
    require(LogonUserW(account.name.c_str(), L".", password.c_str(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &raw), "test account logon");
    Handle token(raw);
    { Impersonation caller(token.get());
      Handle denied(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
      require(!denied && GetLastError() == ERROR_ACCESS_DENIED, "another user read private identity");
      Handle created(CreateFileW(foreign.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, 0, nullptr));
      require(static_cast<bool>(created), "create foreign identity"); }
    // The public fixture ACL lets the test open this file; owner checking must still reject it.
    bool ownership = false;
    try { Descriptor file(barrier::read_private_file(foreign)); }
    catch (const std::runtime_error& error) { ownership = std::string(error.what()).find("another owner") != std::string::npos; }
    require(ownership, "foreign owner was not checked");
    require(NetUserDel(nullptr, account.name.c_str()) == NERR_Success, "remove test account"); account.created = false;
}
int main() {
    struct Test { const char* name; void (*run)(); } tests[] = {
        {"creation", creation}, {"migration", migration}, {"collision", collision}, {"hardlink", hardlink},
        {"symlink", symlink}, {"directory", directory}, {"size limit", size_limit}, {"sharing", sharing},
        {"replacement", replacement}, {"streams", streams}, {"permission failure", permission_failure},
        {"busy writer", busy_writer}, {"extended path", extended_path}, {"other user", other_user}};
    int failed = 0;
    for (auto& test : tests) { try { test.run(); std::cout << "PASS " << test.name << '\n'; }
        catch (const std::exception& error) { ++failed; std::cerr << "FAIL " << test.name << ": " << error.what() << '\n'; } }
    return failed ? 1 : 0;
}
