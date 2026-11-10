/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "PeerTrustStore.h"
#include "base/finally.h"
#include "io/WinPrivateFile.h"
#include <QFile>
#include <QLockFile>
#include <sstream>
#include <stdexcept>
#ifdef _WIN32
#include <io.h>
#else
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <deque>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {
constexpr qint64 limit = 1024 * 1024;
bool valid(const barrier::FingerprintData& peer)
{
    return (peer.algorithm == "sha256" && peer.data.size() == 32) ||
           (peer.algorithm == "sha1" && peer.data.size() == 20);
}
#ifndef _WIN32
std::string file_name(const barrier::fs::path& path)
{
    const auto name = path.filename().native();
    if (path.native().find('\0') != std::string::npos || name.empty() || name == "." || name == "..") {
        throw std::runtime_error("The peer trust path needs a file name.");
    }
    return name;
}
// I check each ancestor before using it, rather than trusting a tidy-looking full path.
int open_trust_directory(const barrier::fs::path& path, bool allow_missing, bool create)
{
    struct Component { std::string name; bool link_target; };
    std::deque<Component> pending;
    const auto enqueue = [&](const barrier::fs::path& input, bool link_target, bool front) {
        std::vector<Component> parts;
        for (const auto& part : input.relative_path()) {
            const auto name = part.native();
            if (name.empty() || name == ".") { continue; }
            if (name == ".." && !link_target) {
                throw std::runtime_error("Parent traversal is unsupported in the peer trust path.");
            }
            parts.push_back({name, link_target});
        }
        if (parts.size() + pending.size() > 256) {
            throw std::runtime_error("The peer trust path has too many components.");
        }
        if (front) { for (auto it = parts.rbegin(); it != parts.rend(); ++it) { pending.push_front(*it); } }
        else { for (const auto& part : parts) { pending.push_back(part); } }
    };
    if (path.native().find('\0') != std::string::npos || path.native().size() > 4096) {
        throw std::runtime_error("The peer trust folder path is invalid or too long.");
    }
    enqueue(path, false, false);
    std::vector<int> folders;
    folders.reserve(257);
    auto cleanup = barrier::finally([&] { for (int fd : folders) { if (fd >= 0) { ::close(fd); } } });
    // FUTURE(BX-004): macOS extended ACLs need checks beyond these ownership/mode rules.
    const auto check = [](int fd, bool final) {
        struct stat info{};
        if (::fstat(fd, &info) != 0 || !S_ISDIR(info.st_mode)) {
            throw std::runtime_error("Cannot inspect the peer trust folder.");
        }
        // FUTURE(BX-007): I want recovery to identify the unsafe ancestor before offering a repair.
        const bool writable = (info.st_mode & (S_IWGRP | S_IWOTH)) != 0;
        const bool shared_root = !final && info.st_uid == 0 && (info.st_mode & S_ISVTX);
        if ((final ? info.st_uid != geteuid() : info.st_uid != 0 && info.st_uid != geteuid()) ||
            (writable && !shared_root)) {
            throw std::runtime_error("The peer trust folder chain has unsafe ownership or write access.");
        }
    };
    const int flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
    const int root = ::open("/", flags);
    if (root < 0) { throw std::runtime_error("Cannot open the filesystem root for peer trust."); }
    folders.push_back(root);
    check(root, pending.empty());
    unsigned links = 0, steps = 0;
    while (!pending.empty()) {
        if (++steps > 512) { throw std::runtime_error("The peer trust folder chain is too complex."); }
        const auto part = pending.front();
        pending.pop_front();
        if (part.name == "..") {
            // Only a checked symlink target can reach this branch.
            if (!part.link_target) { throw std::runtime_error("Invalid peer trust traversal."); }
            if (folders.size() > 1) { ::close(folders.back()); folders.pop_back(); }
            continue;
        }
        const bool final = pending.empty();
        struct stat entry{};
        if (::fstatat(folders.back(), part.name.c_str(), &entry, AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno != ENOENT) { throw std::runtime_error("Cannot inspect a peer trust ancestor."); }
            if (create) {
                if (::mkdirat(folders.back(), part.name.c_str(), 0700) != 0 && errno != EEXIST) {
                    throw std::runtime_error("Cannot create a private peer trust folder.");
                }
                if (::fstatat(folders.back(), part.name.c_str(), &entry, AT_SYMLINK_NOFOLLOW) != 0) {
                    throw std::runtime_error("Cannot inspect the created peer trust folder.");
                }
            } else if (allow_missing) { return -1; }
            else { throw std::runtime_error("The peer trust folder is missing."); }
        }
        if (S_ISLNK(entry.st_mode)) {
            if (final || ++links > 40 || (entry.st_uid != 0 && entry.st_uid != geteuid())) {
                throw std::runtime_error("The peer trust folder chain contains an unsupported link.");
            }
            char target[4097];
            const auto length = ::readlinkat(folders.back(), part.name.c_str(), target, sizeof(target));
            if (length <= 0 || length >= static_cast<ssize_t>(sizeof(target))) {
                throw std::runtime_error("Cannot resolve a peer trust ancestor link.");
            }
            const barrier::fs::path resolved(std::string(target, static_cast<std::size_t>(length)));
            if (resolved.is_absolute()) {
                while (folders.size() > 1) { ::close(folders.back()); folders.pop_back(); }
            }
            enqueue(resolved, true, true);
            continue;
        }
        int fd = ::openat(folders.back(), part.name.c_str(), flags);
        if (fd < 0) { throw std::runtime_error("Cannot open a peer trust ancestor without following links."); }
        auto close_new = barrier::finally([&] { if (fd >= 0) { ::close(fd); } });
        check(fd, final);
        if (folders.size() >= 257) { throw std::runtime_error("The peer trust folder chain is too deep."); }
        folders.push_back(fd);
        fd = -1;
    }
    check(folders.back(), true);
    const int result = folders.back();
    folders.back() = -1;
    return result;
}
class TrustDirectory {
public:
    explicit TrustDirectory(const barrier::fs::path& path, bool allow_missing = false, bool create = false) :
        path_(barrier::fs::absolute(path.empty() ? barrier::fs::path(".") : path))
    {
        descriptor_ = open_trust_directory(path_, allow_missing, create);
    }
    ~TrustDirectory() { if (descriptor_ >= 0) { ::close(descriptor_); } }
    TrustDirectory(const TrustDirectory&) = delete;
    TrustDirectory& operator=(const TrustDirectory&) = delete;
    int descriptor() const { return descriptor_; }
    void check_current() const
    {
        TrustDirectory current(path_);
        struct stat held{}, reopened{};
        if (::fstat(descriptor_, &held) != 0 || ::fstat(current.descriptor(), &reopened) != 0 ||
            held.st_dev != reopened.st_dev || held.st_ino != reopened.st_ino) {
            throw std::runtime_error("The peer trust folder changed during approval. Retry the connection.");
        }
    }
    void publish(const std::string& name, const std::string& bytes) const
    {
        static std::atomic<unsigned long long> sequence{0};
        int fd = -1;
        std::string temporary;
        bool published = false;
        auto cleanup = barrier::finally([&] {
            if (fd >= 0) {
                if (!published) { ::unlinkat(descriptor_, temporary.c_str(), 0); }
                ::close(fd);
            }
        });
        for (int attempt = 0; attempt < 64; ++attempt) {
            temporary = name + ".pending-" + std::to_string(getpid()) + "-" +
                std::to_string(sequence.fetch_add(1, std::memory_order_relaxed));
            fd = ::openat(descriptor_, temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
            if (fd >= 0) { break; }
            if (errno != EEXIST) { throw std::runtime_error("Cannot create a private peer trust replacement."); }
        }
        if (fd < 0 || ::fchmod(fd, 0600) != 0) {
            throw std::runtime_error("Cannot reserve a private peer trust replacement.");
        }
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            const auto written = ::write(fd, bytes.data() + offset, bytes.size() - offset);
            if (written < 0 && errno == EINTR) { continue; }
            if (written <= 0) { throw std::runtime_error("Cannot write the peer trust replacement."); }
            offset += static_cast<std::size_t>(written);
        }
        int synced;
        do { synced = ::fsync(fd); } while (synced < 0 && errno == EINTR);
        if (synced != 0) { throw std::runtime_error("Cannot flush the peer trust replacement."); }
        check_current();
        // 2.4.25: I keep publication and cleanup tied to the folder I actually opened.
        if (::renameat(descriptor_, temporary.c_str(), descriptor_, name.c_str()) != 0) {
            throw std::runtime_error("Cannot publish the peer trust replacement.");
        }
        published = true;
    }
private:
    barrier::fs::path path_;
    int descriptor_ = -1;
};
#endif

barrier::FingerprintDatabase read_descriptor(int descriptor)
{
    barrier::FingerprintDatabase result;
#ifdef _WIN32
    const auto close = [](int fd) { _close(fd); };
#else
    const auto close = [](int fd) { ::close(fd); };
#endif
    auto cleanup = barrier::finally([&] { if (descriptor >= 0) { close(descriptor); } });
#ifndef _WIN32
    struct stat info{};
    if (::fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != geteuid() ||
        info.st_nlink != 1 || (info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        throw std::runtime_error("The peer trust file must have one link, belong to this user and refuse other users' writes.");
    }
    if (info.st_size < 0 || info.st_size > limit) {
        throw std::runtime_error("The peer trust file exceeds the 1 MiB limit.");
    }
#endif
    QFile input;
    if (!input.open(descriptor, QIODevice::ReadOnly, QFileDevice::AutoCloseHandle)) {
        throw std::runtime_error("Cannot read the peer trust file.");
    }
    descriptor = -1;
    const auto bytes = input.read(limit + 1);
    if (input.error() != QFileDevice::NoError || bytes.size() > limit) {
        throw std::runtime_error("The peer trust file could not be read within the 1 MiB limit.");
    }
    std::istringstream encoded(std::string(bytes.constData(), static_cast<std::size_t>(bytes.size())));
    std::string line;
    while (std::getline(encoded, line)) {
        if (!line.empty() && line.back() == '\r') { line.pop_back(); }
        if (line.empty()) { continue; }
        const auto peer = barrier::FingerprintDatabase::parse_db_line(line);
        if (!valid(peer)) {
            throw std::runtime_error("The peer trust file contains an unsupported or malformed entry. Existing approvals have been kept.");
        }
        result.add_trusted(peer);
    }
    return result;
}
#ifndef _WIN32
barrier::FingerprintDatabase read_entry(const TrustDirectory& directory, const std::string& name)
{
    const int fd = ::openat(directory.descriptor(), name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        if (errno == ENOENT) { return {}; }
        throw std::runtime_error("Cannot open the peer trust file.");
    }
    return read_descriptor(fd);
}
#endif
}

barrier::FingerprintDatabase PeerTrustStore::read(const barrier::fs::path& path)
{
#ifdef _WIN32
    // FUTURE(BX-004): check and anchor Windows parent directories too.
    const auto status = barrier::fs::symlink_status(path);
    if (!barrier::fs::exists(status)) { return {}; }
    if (!barrier::fs::is_regular_file(status)) {
        throw std::runtime_error("The peer trust path must be a regular file, not a link or directory.");
    }
    return read_descriptor(barrier::read_private_file(path.native()));
#else
    const auto name = file_name(path);
    TrustDirectory directory(path.parent_path(), true);
    if (directory.descriptor() < 0) { return {}; }
    return read_entry(directory, name);
#endif
}

void PeerTrustStore::approve(const barrier::fs::path& path, const barrier::FingerprintData& peer)
{
    if (peer.algorithm != "sha256" || peer.data.size() != 32) {
        throw std::runtime_error("Only a complete SHA-256 fingerprint can be approved.");
    }
#ifndef _WIN32
    const auto entry = file_name(path);
#endif
#ifdef _WIN32
    if (!path.parent_path().empty()) { barrier::fs::create_directories(path.parent_path()); }
#else
    TrustDirectory directory(path.parent_path(), false, true);
#endif
    const auto name = QString::fromStdString(path.u8string());
    QLockFile lock(name + QStringLiteral(".lock"));
    lock.setStaleLockTime(0);
    if (!lock.tryLock(0)) {
        throw std::runtime_error("The peer trust file could not be locked. Another update may be running; check folder access and retry.");
    }
    // 2.4.23: I merge after approval, under the lock. A dialog isn't a file lock.
#ifdef _WIN32
    auto database = read(path);
#else
    directory.check_current();
    auto database = read_entry(directory, entry);
#endif
    database.add_trusted(peer);
    std::ostringstream encoded;
    database.write_stream(encoded);
    const auto bytes = encoded.str();
    if (bytes.size() > static_cast<std::size_t>(limit)) {
        throw std::runtime_error("Saving this approval would exceed the peer trust file's 1 MiB limit.");
    }
#ifdef _WIN32
    barrier::replace_private_file(path.native(), bytes);
#else
    directory.publish(entry, bytes);
#endif
}
