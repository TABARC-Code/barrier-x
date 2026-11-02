/*
 * Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE.
 */
#pragma once
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace barrier { namespace localipc {
constexpr wchar_t service_pipe[] = L"\\\\.\\pipe\\barrier-x-management-v1";
class Handle {
public:
    explicit Handle(HANDLE value = nullptr) : value_(value) { }
    ~Handle() { reset(); }
    Handle(Handle&& other) noexcept : value_(other.release()) { }
    Handle& operator=(Handle&& other) noexcept { reset(other.release()); return *this; }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
    explicit operator bool() const { return value_ && value_ != INVALID_HANDLE_VALUE; }
    HANDLE release() { HANDLE value = value_; value_ = nullptr; return value; }
    void reset(HANDLE value = nullptr) {
        if (*this) { CloseHandle(value_); }
        value_ = value;
    }
private:
    HANDLE value_;
};

enum class Role { Gui = 1, Node = 2 };
enum class Operation { Hello, Command, Log, Shutdown };
// Every pending operation is cancelled and drained before its OVERLAPPED dies.
DWORD transfer(HANDLE pipe, void* data, DWORD size, bool writing,
               HANDLE stop, DWORD timeout = 5000);
Handle connect(const std::wstring& name, DWORD expectedServer);
Handle connectService(bool wait = false);
bool elevatedAdministrator();

class Policy {
public:
    // The foreground mode uses the process token, never a failed service lookup.
    explicit Policy(bool service);
    void child(HANDLE process);
    bool gui(HANDLE token, bool management) const;
    bool node(HANDLE token, DWORD pid) const;
    bool acquire() { return live_.fetch_add(1) < 24 || (live_.fetch_sub(1), false); }
    void release() { live_.fetch_sub(1); }
private:
    Handle sessionToken() const;
    bool service_;
    mutable std::mutex mutex_;
    Handle child_;
    std::atomic<unsigned> live_{0};
};

struct Peer {
    Handle token;
    Handle process;
    bool leased = false;
    ~Peer() { if (leased && policy) { policy->release(); } }
    DWORD pid = 0;
    Role role = Role::Gui;
    std::shared_ptr<Policy> policy;
    std::atomic<bool> connected{true};
    bool allows(Operation operation) const;
};
struct Accepted {
    Handle pipe;
    std::shared_ptr<Peer> peer;
    std::array<char, 5> greeting{};
};
class Listener {
public:
    Listener(std::wstring name, std::shared_ptr<Policy> policy);
    Accepted accept(HANDLE stop);
private:
    Handle instance(bool first);
    std::wstring name_;
    std::shared_ptr<Policy> policy_;
    Handle next_;
};
} }
#endif
