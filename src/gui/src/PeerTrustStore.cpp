/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "PeerTrustStore.h"
#include "base/finally.h"
#include "io/WinPrivateFile.h"
#include "io/PrivateDirectory.h"
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
class TrustDirectory {
public:
    explicit TrustDirectory(const barrier::fs::path& path, bool allow_missing = false, bool create = false) :
        directory_(path, create ? barrier::PrivateDirectoryMode::Create :
                   allow_missing ? barrier::PrivateDirectoryMode::AllowMissing : barrier::PrivateDirectoryMode::Existing)
    {}
    int descriptor() const { return directory_.descriptor(); }
    void check_current() const { directory_.check_current(); }
    void publish(const std::string& name, const std::string& bytes) const
    {
        static std::atomic<unsigned long long> sequence{0};
        int fd = -1;
        std::string temporary;
        bool published = false;
        auto cleanup = barrier::finally([&] {
            if (fd >= 0) {
                if (!published) { ::unlinkat(descriptor(), temporary.c_str(), 0); }
                ::close(fd);
            }
        });
        for (int attempt = 0; attempt < 64; ++attempt) {
            temporary = name + ".pending-" + std::to_string(getpid()) + "-" +
                std::to_string(sequence.fetch_add(1, std::memory_order_relaxed));
            fd = ::openat(descriptor(), temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
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
        if (::renameat(descriptor(), temporary.c_str(), descriptor(), name.c_str()) != 0) {
            throw std::runtime_error("Cannot publish the peer trust replacement.");
        }
        published = true;
    }
private:
    barrier::PrivateDirectory directory_;
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
