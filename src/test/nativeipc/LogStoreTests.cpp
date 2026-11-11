/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "io/LogStore.h"
#include "io/WinPrivateFile.h"
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <io.h>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <vector>
namespace {
void require(bool value, const char* reason) { if (!value) { throw std::runtime_error(reason); } }
struct Handle {
    HANDLE value;
    explicit Handle(HANDLE input) : value(input) {}
    ~Handle() { if (value != INVALID_HANDLE_VALUE && value) { CloseHandle(value); } }
    Handle(const Handle&) = delete;
};
struct Descriptor {
    int value;
    explicit Descriptor(int input) : value(input) {}
    ~Descriptor() { if (value >= 0) { _close(value); } }
    Descriptor(const Descriptor&) = delete;
};
void protect_directory(const barrier::fs::path& path) {
    PSECURITY_DESCRIPTOR owner_descriptor = nullptr;
    PSID owner = nullptr;
    require(GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
                                  OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr,
                                  &owner_descriptor) == ERROR_SUCCESS, "read fixture owner");
    LPWSTR owner_text = nullptr;
    require(ConvertSidToStringSidW(owner, &owner_text), "format fixture owner");
    const std::wstring sddl = L"D:P(A;OICI;FA;;;" + std::wstring(owner_text) + L")(A;OICI;FA;;;SY)";
    LocalFree(owner_text); LocalFree(owner_descriptor);
    PSECURITY_DESCRIPTOR raw = nullptr;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &raw, nullptr),
            "private fixture ACL");
    PACL acl = nullptr; BOOL present = FALSE, defaulted = FALSE;
    require(GetSecurityDescriptorDacl(raw, &present, &acl, &defaulted) && present && acl, "read private fixture ACL");
    const DWORD error = SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
    LocalFree(raw); require(error == ERROR_SUCCESS, "protect fixture folder");
}
struct Fixture {
    barrier::fs::path directory;
    std::vector<barrier::fs::path> files;
    Fixture() {
        wchar_t temporary[MAX_PATH]{};
        auto length = GetTempPathW(MAX_PATH, temporary);
        require(length && length < MAX_PATH, "temporary folder");
        directory = barrier::fs::path(temporary) / (L"BXLogs-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
        require(CreateDirectoryW(directory.c_str(), nullptr), "create fixture folder");
        protect_directory(directory);
    }
    barrier::fs::path path(const wchar_t* name) { files.push_back(directory / name); return files.back(); }
    ~Fixture() {
        for (const auto& file : files) { DeleteFileW(file.c_str()); }
        RemoveDirectoryW(directory.c_str());
    }
};
constexpr std::time_t now = 1700000000;
std::string read(const barrier::fs::path& path) {
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
    require(file.value != INVALID_HANDLE_VALUE, "read fixture");
    LARGE_INTEGER size{}; require(GetFileSizeEx(file.value, &size) && size.QuadPart >= 0 && size.QuadPart <= 3*1024*1024, "fixture size");
    std::string bytes(static_cast<std::size_t>(size.QuadPart), '\0');
    DWORD count = 0;
    require(ReadFile(file.value, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) && count == bytes.size(), "read fixture bytes");
    return bytes;
}
void put(const barrier::fs::path& path, const std::string& bytes) {
    Descriptor file(barrier::create_private_file(path.native()));
    require(_write(file.value, bytes.data(), static_cast<unsigned>(bytes.size())) == static_cast<int>(bytes.size()), "write fixture");
}
void rejected(const std::function<void()>& operation) {
    bool failed = false;
    try { operation(); } catch (const std::exception&) { failed = true; }
    require(failed, "unsafe log operation accepted");
}
std::wstring security(const barrier::fs::path& path) {
    PSECURITY_DESCRIPTOR raw = nullptr;
    require(GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr, &raw) == ERROR_SUCCESS, "read fixture security");
    LPWSTR text = nullptr;
    const auto converted = ConvertSecurityDescriptorToStringSecurityDescriptorW(raw, SDDL_REVISION_1,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &text, nullptr);
    LocalFree(raw);
    require(converted, "describe fixture security");
    const std::wstring result(text); LocalFree(text); return result;
}
void choices_and_expiry() {
    Fixture f; const auto path = f.path(L"barrier.log");
    for (const int days : {0,5,10,12,15,22,28,30,60}) {
        require(barrier::valid_log_retention(days), "documented choice rejected");
        barrier::append_log(path, "private", 0, now);
        require(barrier::expire_logs(path, days, now - 1) == 0, "future log cleared");
        if (days) {
            require(barrier::expire_logs(path, days, now + days*86400 - 1) == 0, "early expiry");
            require(barrier::expire_logs(path, days, now + days*86400) == 1 && read(path).empty(), "expiry boundary");
        } else {
            require(barrier::expire_logs(path, 0, now + 100*86400) == 0 && !read(path).empty(), "off cleared logs");
            barrier::clear_logs(path);
        }
    }
    for (int days : {-1,1,6,21,31,61}) {
        require(!barrier::valid_log_retention(days), "unsupported choice accepted");
        rejected([&] { barrier::expire_logs(path, days, now); });
    }
}
void clear_scope_and_resume() {
    Fixture f; const auto path = f.path(L"barrier.log"), backup = f.path(L"barrier.log.1"), key = f.path(L"identity.pem");
    barrier::append_log(path, "active", 0, now); barrier::append_log(backup, "archive", 0, now); put(key, "keep identity");
    require(barrier::clear_logs(path) == 2 && read(path).empty() && read(backup).empty(), "clear current and backup");
    require(read(key) == "keep identity", "unrelated identity changed");
    barrier::append_log(path, "fresh entry", 5, now + 1);
    require(read(path).find("fresh entry") != std::string::npos, "logging didn't resume");
}
void independent_archive_age() {
    Fixture f; auto path = f.path(L"barrier.log"), backup = f.path(L"barrier.log.1");
    barrier::append_log(path, "old", 0, now); barrier::append_log(path, "newer", 0, now + 4*86400);
    barrier::append_log(backup, "recent archive", 0, now + 4*86400);
    require(barrier::expire_logs(path, 5, now + 5*86400) == 1 && read(path).empty(), "whole-file expiry");
    require(read(backup).find("recent archive") != std::string::npos, "fresh archive cleared");
}
void busy_files() {
    Fixture f; auto path = f.path(L"barrier.log"), backup = f.path(L"barrier.log.1");
    barrier::append_log(path, "keep current", 0, now); barrier::append_log(backup, "keep archive", 0, now);
    const auto active_bytes = read(path), archive_bytes = read(backup);
    for (const auto& busy : {path, backup}) {
        Handle held(CreateFileW(busy.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
        require(held.value != INVALID_HANDLE_VALUE, "hold busy log");
        rejected([&] { barrier::clear_logs(path); });
        rejected([&] { barrier::expire_logs(path, 5, now + 6*86400); });
        rejected([&] { barrier::append_log(path, "must not append", 0, now); });
    }
    require(read(path) == active_bytes && read(backup) == archive_bytes, "busy refusal changed logs");
}
void unknown_backup() {
    Fixture f; auto path = f.path(L"barrier.log"), backup = f.path(L"barrier.log.1");
    barrier::append_log(path, "keep", 0, now); put(backup, "not an application log");
    const auto before = read(path); const auto acl = security(backup);
    rejected([&] { barrier::clear_logs(path); });
    rejected([&] { barrier::expire_logs(path, 5, now + 6*86400); });
    require(read(path) == before && read(backup) == "not an application log" && security(backup) == acl, "unknown backup changed");
}
void broad_acl() {
    Fixture f; auto path = f.path(L"barrier.log"); barrier::append_log(path, "keep", 0, now);
    const auto before = read(path);
    PSECURITY_DESCRIPTOR raw = nullptr;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;WD)", SDDL_REVISION_1, &raw, nullptr), "public log ACL");
    PACL acl = nullptr; BOOL present = FALSE, defaulted = FALSE;
    require(GetSecurityDescriptorDacl(raw, &present, &acl, &defaulted), "public DACL");
    const auto error = SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
    LocalFree(raw); require(error == ERROR_SUCCESS, "apply public log ACL");
    const auto original = security(path);
    rejected([&] { barrier::clear_logs(path); });
    rejected([&] { barrier::append_log(path, "must not append", 0, now); });
    require(security(path) == original && read(path) == before, "public log ACL or bytes changed");
}
void inherited_acl() {
    Fixture f; auto path = f.path(L"barrier.log");
    { Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, 0, nullptr));
      require(file.value != INVALID_HANDLE_VALUE, "inherited log fixture");
      const std::string bytes = "# barrier-x log 1 1700000000\nprivate\n"; DWORD count = 0;
      require(WriteFile(file.value, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) && count == bytes.size(), "write inherited log"); }
    const auto original = security(path); const auto before = read(path);
    rejected([&] { barrier::clear_logs(path); });
    require(security(path) == original && read(path) == before, "inherited ACL or contents changed");
}
void links() {
    Fixture f; auto target = f.path(L"target.log"), hard = f.path(L"hard.log"), symbolic = f.path(L"symbolic.log");
    barrier::append_log(target, "keep", 0, now); const auto before = read(target);
    require(CreateHardLinkW(hard.c_str(), target.c_str(), nullptr), "hardlink fixture");
    rejected([&] { barrier::clear_logs(hard); }); rejected([&] { barrier::clear_logs(target); });
    require(DeleteFileW(hard.c_str()), "remove hardlink");
    require(CreateSymbolicLinkW(symbolic.c_str(), target.c_str(), 2) || CreateSymbolicLinkW(symbolic.c_str(), target.c_str(), 0), "symlink fixture");
    rejected([&] { barrier::clear_logs(symbolic); });
    require(read(target) == before, "linked target changed");
}
void streams_and_oversize() {
    Fixture f; auto path = f.path(L"barrier.log"); barrier::append_log(path, "keep", 0, now);
    const auto before = read(path); const auto stream = barrier::fs::path(path.native() + L":other");
    { Handle file(CreateFileW(stream.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, 0, nullptr));
      require(file.value != INVALID_HANDLE_VALUE, "alternate stream fixture");
      DWORD count = 0; require(WriteFile(file.value, "keep stream", 11, &count, nullptr) && count == 11, "write alternate stream"); }
    rejected([&] { barrier::clear_logs(stream); }); rejected([&] { barrier::append_log(stream, "no", 0, now); });
    require(read(path) == before && read(stream) == "keep stream", "stream rejection changed contents");
    { Descriptor file(barrier::edit_private_log(path.native())); require(_chsize_s(file.value, 2*1024*1024+1) == 0, "oversized fixture"); }
    rejected([&] { barrier::clear_logs(path); });
    require(read(path).size() == 2*1024*1024+1, "oversized file truncated");
}
void unicode_and_rotation() {
    Fixture f; auto path = f.path(L"log-\u65e5\u672c\u8a9e.log"), backup = f.path(L"log-\u65e5\u672c\u8a9e.log.1");
    for (int i=0; i<18; ++i) { barrier::append_log(path, std::string(64000, 'x'), 0, now); }
    require(read(path).size() < 1024*1024 && read(backup).size() < 1024*1024, "rotation bound");
    require(barrier::expire_logs(path, 5, now + 5*86400) == 2, "rotation lost age");
    barrier::append_log(path, std::string(200000, 'y'), 0, now);
    require(read(path).size() < 66000 && read(path).find("[entry shortened]") != std::string::npos, "entry bound");
}
void legacy_and_missing() {
    Fixture f; auto path = f.path(L"barrier.log");
    require(barrier::clear_logs(path) == 0 && !barrier::fs::exists(path), "missing log created");
    put(path, "[2023-01-01T00:00:00] INFO: legacy\n");
    barrier::append_log(path, "later", 0, now);
    require(read(path).find("later") != std::string::npos && barrier::expire_logs(path, 60, now) == 1, "legacy retention");
}
void checked_handle() {
    Fixture f; auto path = f.path(L"barrier.log"), moved = f.path(L"moved.log");
    barrier::append_log(path, "private", 0, now);
    Descriptor file(barrier::edit_private_log(path.native()));
    const auto raw = reinterpret_cast<HANDLE>(_get_osfhandle(file.value)); DWORD flags = 0;
    require(GetHandleInformation(raw, &flags) && !(flags & HANDLE_FLAG_INHERIT), "log handle inherited");
    require(!MoveFileW(path.c_str(), moved.c_str()), "open log moved");
    rejected([&] { barrier::clear_logs(path); });
}
}
int main() {
    struct Test { const char* name; void (*run)(); } tests[] = {
        {"choices and expiry", choices_and_expiry}, {"clear scope and resume", clear_scope_and_resume},
        {"independent archive age", independent_archive_age}, {"busy files", busy_files},
        {"unknown backup", unknown_backup}, {"broad ACL", broad_acl}, {"inherited ACL", inherited_acl},
        {"links", links}, {"streams and size", streams_and_oversize}, {"Unicode and rotation", unicode_and_rotation},
        {"legacy and missing", legacy_and_missing}, {"checked handle", checked_handle}};
    int failed = 0;
    for (const auto& test : tests) {
        try { test.run(); std::cout << "PASS " << test.name << '\n'; }
        catch (const std::exception& error) { ++failed; std::cerr << "FAIL " << test.name << ": " << error.what() << '\n'; }
    }
    return failed ? 1 : 0;
}
