/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "PeerTrustStore.h"
#include "base/finally.h"
#include "io/WinPrivateFile.h"
#include <QFile>
#include <QLockFile>
#include <QSaveFile>
#include <sstream>
#include <stdexcept>
#ifdef _WIN32
#include <io.h>
#else
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
}

barrier::FingerprintDatabase PeerTrustStore::read(const barrier::fs::path& path)
{
    barrier::FingerprintDatabase result;
    // FUTURE(BX-004): anchor the parent directory as well as checking the final file.
    const auto status = barrier::fs::symlink_status(path);
    if (!barrier::fs::exists(status)) { return result; }
    if (!barrier::fs::is_regular_file(status)) {
        throw std::runtime_error("The peer trust path must be a regular file, not a link or directory.");
    }
#ifdef _WIN32
    int descriptor = barrier::read_private_file(path.native());
    const auto close = [](int fd) { _close(fd); };
#else
    int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    const auto close = [](int fd) { ::close(fd); };
#endif
    if (descriptor < 0) { throw std::runtime_error("Cannot open the peer trust file."); }
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

void PeerTrustStore::approve(const barrier::fs::path& path, const barrier::FingerprintData& peer)
{
    if (peer.algorithm != "sha256" || peer.data.size() != 32) {
        throw std::runtime_error("Only a complete SHA-256 fingerprint can be approved.");
    }
    barrier::fs::create_directories(path.parent_path());
    const auto name = QString::fromStdString(path.u8string());
    QLockFile lock(name + QStringLiteral(".lock"));
    lock.setStaleLockTime(0);
    if (!lock.tryLock(0)) {
        throw std::runtime_error("The peer trust file could not be locked. Another update may be running; check folder access and retry.");
    }
    // 2.4.23: I merge after approval, under the lock. A dialog isn't a file lock.
    auto database = read(path);
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
    QSaveFile output(name);
    output.setDirectWriteFallback(false);
    if (!output.open(QIODevice::WriteOnly) ||
        !output.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner) ||
        output.write(bytes.data(), static_cast<qint64>(bytes.size())) != static_cast<qint64>(bytes.size()) ||
        !output.commit()) {
        throw std::runtime_error("Cannot save the peer approval: " + output.errorString().toStdString());
    }
#endif
}
