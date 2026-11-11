/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "LogStore.h"
#include <algorithm>
#include <cerrno>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <memory>
#ifdef _WIN32
#include "WinPrivateFile.h"
#include <io.h>
#else
#include "PrivateDirectory.h"
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
namespace barrier {
namespace {
constexpr std::size_t maximum = 2 * 1024 * 1024;
constexpr std::size_t rotation = 1024 * 1024;
const std::string marker = "# barrier-x log 1 ";
struct File {
    int fd = -1;
    std::size_t size = 0;
    std::time_t started = 0;
    ~File() {
        if (fd >= 0) {
#ifdef _WIN32
            _close(fd);
#else
            ::close(fd);
#endif
        }
    }
    void seek(long offset) {
#ifdef _WIN32
        if (_lseek(fd, offset, SEEK_SET) < 0) { throw std::runtime_error("Cannot seek log"); }
#else
        if (::lseek(fd, offset, SEEK_SET) < 0) { throw std::runtime_error("Cannot seek log"); }
#endif
    }
    std::string read(std::size_t limit) {
        seek(0);
        std::string bytes;
        char chunk[4096];
        while (bytes.size() < limit) {
            const auto wanted = std::min(sizeof(chunk), limit - bytes.size());
#ifdef _WIN32
            const auto count = _read(fd, chunk, static_cast<unsigned>(wanted));
#else
            const auto count = ::read(fd, chunk, wanted);
#endif
            if (count < 0 && errno == EINTR) { continue; }
            if (count < 0) { throw std::runtime_error("Cannot read log"); }
            if (!count) { break; }
            bytes.append(chunk, static_cast<std::size_t>(count));
        }
        return bytes;
    }
    void write(const std::string& bytes) {
        std::size_t offset = 0;
        while (offset < bytes.size()) {
#ifdef _WIN32
            const auto count = _write(fd, bytes.data() + offset, static_cast<unsigned>(bytes.size() - offset));
#else
            const auto count = ::write(fd, bytes.data() + offset, bytes.size() - offset);
#endif
            if (count < 0 && errno == EINTR) { continue; }
            if (count <= 0) { throw std::runtime_error("Cannot write log"); }
            offset += static_cast<std::size_t>(count);
        }
        size += bytes.size();
    }
    void clear() {
        // I clear the held file, so an active writer doesn't carry on in an unlinked log.
#ifdef _WIN32
        if (_chsize_s(fd, 0) != 0 || _commit(fd) != 0) { throw std::runtime_error("Cannot clear log"); }
#else
        if (::ftruncate(fd, 0) != 0 || ::fsync(fd) != 0) { throw std::runtime_error("Cannot clear log"); }
#endif
        seek(0);
        size = 0;
        started = 0;
    }
    void inspect() {
#ifdef _WIN32
        const auto length = _filelengthi64(fd);
        if (length < 0 || static_cast<unsigned long long>(length) > maximum) { throw std::runtime_error("Log exceeds safety limit"); }
        size = static_cast<std::size_t>(length);
#else
        struct stat info{};
        if (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != geteuid() || info.st_nlink != 1 ||
            (info.st_mode & 0022) || info.st_size < 0 || static_cast<unsigned long long>(info.st_size) > maximum) {
            throw std::runtime_error("Log ownership, links, permissions or size are unsafe");
        }
        size = static_cast<std::size_t>(info.st_size);
#endif
        if (!size) {
#ifndef _WIN32
            if (::fchmod(fd, 0600) != 0) { throw std::runtime_error("Cannot restrict log access"); }
#endif
            return;
        }
        const auto prefix = read(256);
        const auto line = prefix.substr(0, prefix.find('\n'));
        if (line.compare(0, marker.size(), marker) == 0) {
            const auto value = line.substr(marker.size());
            if (value.empty() || value.size() > 12 || value.find_first_not_of("0123456789") != std::string::npos) {
                throw std::runtime_error("Invalid log age marker");
            }
            const auto stamp = std::stoull(value);
            started = static_cast<std::time_t>(stamp);
            if (started < 0 || static_cast<unsigned long long>(started) != stamp) { throw std::runtime_error("Invalid log age"); }
        } else {
            std::tm stamp{};
            stamp.tm_isdst = -1;
            std::istringstream input(line);
            input >> std::get_time(&stamp, "[%Y-%m-%dT%H:%M:%S]");
            if (input.fail() || stamp.tm_year < 100) { throw std::runtime_error("File isn't a recognised application log"); }
            started = std::mktime(&stamp);
            if (started < 0) { throw std::runtime_error("Invalid legacy log date"); }
        }
#ifndef _WIN32
        if (::fchmod(fd, 0600) != 0) { throw std::runtime_error("Cannot restrict log access"); }
#endif
    }
    bool expired(int days, std::time_t now) const {
        return size && now >= started && std::difftime(now, started) >= static_cast<double>(days) * 86400;
    }
};
class Logs {
public:
    explicit Logs(const fs::path& path, bool create = false) : path_(path) {
        if (path.native().empty() || path.u8string().find('\0') != std::string::npos ||
            path.filename().empty() || path.filename() == "." || path.filename() == "..") {
            throw std::runtime_error("A valid log filename is required");
        }
#ifndef _WIN32
        directory_ = std::make_unique<PrivateDirectory>(path.parent_path(), create ? PrivateDirectoryMode::Create : PrivateDirectoryMode::AllowMissing);
#endif
    }
    std::unique_ptr<File> open(bool backup, bool create) {
        auto file = std::make_unique<File>();
        auto path = path_;
        if (backup) { path += ".1"; }
#ifdef _WIN32
        // Parent handles reject junctions and stay pinned. FUTURE(BX-033): inherited ACL policy still needs native review.
        if (!fs::exists(fs::symlink_status(path))) {
            if (!create) { return {}; }
            const int created = create_private_file(path.native());
            _close(created);
        }
        file->fd = edit_private_log(path.native());
#else
        if (directory_->descriptor() < 0) {
            if (create) { throw std::runtime_error("Log folder is missing"); }
            return {};
        }
        const int flags = O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
        file->fd = ::openat(directory_->descriptor(), path.filename().c_str(), flags);
        if (file->fd < 0 && errno == ENOENT && create) {
            file->fd = ::openat(directory_->descriptor(), path.filename().c_str(), flags | O_CREAT | O_EXCL, 0600);
        }
        if (file->fd < 0) {
            if (errno == ENOENT && !create) { return {}; }
            throw std::runtime_error("Cannot open log safely");
        }
        if (::flock(file->fd, LOCK_EX | LOCK_NB) != 0) { throw std::runtime_error("Log is busy"); }
        directory_->check_current();
#endif
        file->inspect();
        return file;
    }
private:
    fs::path path_;
#ifndef _WIN32
    std::unique_ptr<PrivateDirectory> directory_;
#endif
};
std::string header(std::time_t now) { return marker + std::to_string(now) + "\n"; }
}
bool valid_log_retention(int days) {
    for (const int choice : {0, 5, 10, 12, 15, 22, 28, 30, 60}) { if (days == choice) { return true; } }
    return false;
}
unsigned clear_logs(const fs::path& path) {
    Logs logs(path);
    auto active = logs.open(false, false);
    auto backup = logs.open(true, false);
    unsigned cleared = 0;
    for (auto* file : {active.get(), backup.get()}) {
        if (file && file->size) { file->clear(); ++cleared; }
    }
    return cleared;
}
unsigned expire_logs(const fs::path& path, int days, std::time_t now) {
    if (!valid_log_retention(days)) { throw std::invalid_argument("Invalid log retention"); }
    if (!days) { return 0; }
    Logs logs(path);
    auto active = logs.open(false, false);
    auto backup = logs.open(true, false);
    unsigned cleared = 0;
    for (auto* file : {active.get(), backup.get()}) {
        if (file && file->expired(days, now)) { file->clear(); ++cleared; }
    }
    return cleared;
}
void append_log(const fs::path& path, const std::string& message, int days, std::time_t now) {
    if (!valid_log_retention(days) || now < 0) { throw std::invalid_argument("Invalid log retention or clock"); }
    Logs logs(path, true);
    auto active = logs.open(false, true);
    auto backup = logs.open(true, false);
    for (auto* file : {active.get(), backup.get()}) {
        if (days && file && file->expired(days, now)) { file->clear(); }
    }
    const auto line = message.substr(0, 64 * 1024) + (message.size() > 64 * 1024 ? " [entry shortened]\n" : "\n");
    if (active->size + line.size() > rotation) {
        if (!backup) { backup = logs.open(true, true); }
        const auto previous = active->read(maximum);
        backup->clear();
        backup->write(previous);
        active->clear();
    }
    active->seek(static_cast<long>(active->size));
    if (!active->size) { active->write(header(now)); }
    active->write(line);
}
}
