/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "../../lib/ipc/WinLocalPipe.h"
#include <future>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <lm.h>
#include <bcrypt.h>
using namespace barrier::localipc;
void require(bool condition, const char* message) { if (!condition) { throw std::runtime_error(message); } }
struct Fixture {
    std::wstring name = L"\\\\.\\pipe\\barrier-native-test-" + std::to_wstring(GetCurrentProcessId()) +
                        L"-" + std::to_wstring(GetTickCount64());
    std::shared_ptr<Policy> policy = std::make_shared<Policy>(false);
    Handle stop{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    Listener listener{name, policy};
    std::future<Accepted> task;
    ~Fixture() { SetEvent(stop.get()); if (task.valid()) { task.wait(); } }
    Handle client() {
        task = std::async(std::launch::async, [this] { return listener.accept(stop.get()); });
        return connect(name, GetCurrentProcessId());
    }
    Accepted hello(Handle& pipe, char role) {
        char greeting[] = {'I','H','E','L',role};
        require(transfer(pipe.get(), greeting, sizeof(greeting), true, stop.get()) == 5, "greeting write");
        return task.get();
    }
};
void authenticatedGui()
{
    Fixture f;
    auto client = f.client();
    auto accepted = f.hello(client, 1);
    require(accepted.peer && accepted.peer->allows(Operation::Log), "own logon must read logs");
    require(accepted.peer->allows(Operation::Command) == elevatedAdministrator(), "command requires elevated administrator");
    require(!accepted.peer->allows(Operation::Shutdown), "GUI cannot act as engine");
    accepted.peer->connected.store(false);
    require(!accepted.peer->allows(Operation::Command), "closed credential cannot authorise queued request");
}
void ownedNode()
{
    Fixture f;
    f.policy->child(GetCurrentProcess());
    auto client = f.client();
    auto accepted = f.hello(client, 2);
    require(accepted.peer->allows(Operation::Shutdown), "retained child receives shutdown");
    require(!accepted.peer->allows(Operation::Command), "child cannot change command");
    f.policy->child(nullptr);
    require(!accepted.peer->allows(Operation::Shutdown), "replaced child loses access");
}
void forgedNode()
{
    Fixture f;
    auto client = f.client();
    bool rejected = false;
    try { f.hello(client, 2); } catch (...) { rejected = true; }
    require(rejected, "unregistered process claimed node role");
}
void wrongServer()
{
    Fixture f;
    bool rejected = false;
    try { auto pipe = connect(f.name, GetCurrentProcessId() + 1); } catch (...) { rejected = true; }
    require(rejected, "competing server was trusted");
}
void firstInstance()
{
    Fixture f;
    bool rejected = false;
    try { Listener duplicate(f.name, f.policy); } catch (...) { rejected = true; }
    require(rejected, "second listener took the endpoint");
}
void malformedGreeting()
{
    Fixture f;
    auto client = f.client();
    bool rejected = false;
    try { f.hello(client, 99); } catch (...) { rejected = true; }
    require(rejected, "malformed greeting accepted");
}
void cancelAccept()
{
    Fixture f;
    f.task = std::async(std::launch::async, [&f] { return f.listener.accept(f.stop.get()); });
    SetEvent(f.stop.get());
    require(f.task.wait_for(std::chrono::seconds(2)) == std::future_status::ready, "accept cancellation blocked");
    require(!f.task.get().pipe, "cancelled accept returned client");
}
struct Impersonation {
    explicit Impersonation(HANDLE token) { require(ImpersonateLoggedOnUser(token), "test impersonation"); }
    ~Impersonation() { if (!RevertToSelf()) { std::terminate(); } }
};
void filteredCallerReadOnly()
{
    Fixture f;
    f.task = std::async(std::launch::async, [&f] { return f.listener.accept(f.stop.get()); });
    HANDLE primaryRaw = nullptr;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &primaryRaw), "process token");
    Handle primary(primaryRaw);
    BYTE adminSid[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(adminSid);
    require(CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSid, &size), "administrator SID");
    SID_AND_ATTRIBUTES disabled{adminSid, 0};
    HANDLE filteredRaw = nullptr;
    require(CreateRestrictedToken(primary.get(), DISABLE_MAX_PRIVILEGE, 1, &disabled, 0, nullptr, 0, nullptr, &filteredRaw), "filtered token");
    Handle filtered(filteredRaw);
    Accepted accepted;
    {
        Impersonation caller(filtered.get());
        auto client = connect(f.name, GetCurrentProcessId());
        accepted = f.hello(client, 1);
        require(accepted.peer->allows(Operation::Log), "same logon must retain log access");
        require(!accepted.peer->allows(Operation::Command), "filtered caller changed service command");
    }
}
void restrictedCaller()
{
    Fixture f;
    f.task = std::async(std::launch::async, [&f] { return f.listener.accept(f.stop.get()); });
    HANDLE primaryRaw = nullptr;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &primaryRaw), "process token");
    Handle primary(primaryRaw);
    BYTE worldSid[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(worldSid);
    require(CreateWellKnownSid(WinWorldSid, nullptr, worldSid, &size), "restricting SID");
    SID_AND_ATTRIBUTES restricting{worldSid, 0};
    HANDLE restrictedRaw = nullptr;
    require(CreateRestrictedToken(primary.get(), DISABLE_MAX_PRIVILEGE, 0, nullptr, 0, nullptr, 1, &restricting, &restrictedRaw), "restricted token");
    Handle restricted(restrictedRaw);
    bool rejected = false;
    {
        Impersonation caller(restricted.get());
        try {
            auto client = connect(f.name, GetCurrentProcessId());
            f.hello(client, 1);
        }
        catch (...) { rejected = true; }
    }
    require(rejected, "restricted caller obtained access");
}

void otherLocalUser()
{
    Fixture f;
    struct Account {
        std::wstring name = L"BXIPC" + std::to_wstring(GetCurrentProcessId()) +
                            std::to_wstring(GetTickCount64() % 1000000);
        bool created = false;
        ~Account() { if (created) { NetUserDel(nullptr, name.c_str()); } }
    } account;
    UCHAR random[24];
    require(BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0, "test account randomness");
    std::wstring password = L"Bx9!";
    for (auto value : random) {
        password += L"0123456789abcdef"[value >> 4];
        password += L"0123456789abcdef"[value & 15];
    }
    USER_INFO_1 user{};
    user.usri1_name = const_cast<wchar_t*>(account.name.c_str());
    user.usri1_password = const_cast<wchar_t*>(password.c_str());
    user.usri1_priv = USER_PRIV_USER;
    user.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT;
    DWORD parameter = 0;
    require(NetUserAdd(nullptr, 1, reinterpret_cast<BYTE*>(&user), &parameter) == NERR_Success, "create second local user");
    account.created = true;
    HANDLE raw = nullptr;
    require(LogonUserW(account.name.c_str(), L".", password.c_str(), LOGON32_LOGON_INTERACTIVE,
                       LOGON32_PROVIDER_DEFAULT, &raw), "second-user logon");
    Handle token(raw);
    f.task = std::async(std::launch::async, [&f] { return f.listener.accept(f.stop.get()); });
    bool rejected = false;
    {
        Impersonation caller(token.get());
        auto client = connect(f.name, GetCurrentProcessId());
        try { f.hello(client, 1); } catch (...) { rejected = true; }
    }
    require(rejected, "second local user read another logon's logs");
    require(NetUserDel(nullptr, account.name.c_str()) == NERR_Success, "remove second local user");
    account.created = false;
}

int main()
{
    struct Test { const char* name; void (*run)(); };
    const Test tests[] = {{"authenticated GUI", authenticatedGui}, {"owned node", ownedNode},
        {"forged node", forgedNode}, {"wrong server", wrongServer}, {"first instance", firstInstance},
        {"malformed greeting", malformedGreeting}, {"cancel accept", cancelAccept}, {"filtered caller", filteredCallerReadOnly}, {"restricted caller", restrictedCaller}, {"second local user", otherLocalUser}};
    try {
        for (const auto& test : tests) { test.run(); std::cout << "PASS " << test.name << '\n'; }
        std::cout << "10 native pipe tests passed\n";
    }
    catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
