/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "PrivateDirectory.h"
#ifndef _WIN32
#include "base/finally.h"
#include <cerrno>
#include <deque>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
namespace barrier {
namespace {
// I check each ancestor before using it, rather than trusting a tidy-looking full path.
int open_private_directory(const barrier::fs::path& path, bool allow_missing, bool create)
{
    struct Component { std::string name; bool link_target; };
    std::deque<Component> pending;
    const auto enqueue = [&](const barrier::fs::path& input, bool link_target, bool front) {
        std::vector<Component> parts;
        for (const auto& part : input.relative_path()) {
            const auto name = part.native();
            if (name.empty() || name == ".") { continue; }
            if (name == ".." && !link_target) {
                throw std::runtime_error("Parent traversal is unsupported in the private storage path.");
            }
            parts.push_back({name, link_target});
        }
        if (parts.size() + pending.size() > 256) {
            throw std::runtime_error("The private storage path has too many components.");
        }
        if (front) { for (auto it = parts.rbegin(); it != parts.rend(); ++it) { pending.push_front(*it); } }
        else { for (const auto& part : parts) { pending.push_back(part); } }
    };
    if (path.native().find('\0') != std::string::npos || path.native().size() > 4096) {
        throw std::runtime_error("The private storage folder path is invalid or too long.");
    }
    enqueue(path, false, false);
    std::vector<int> folders;
    folders.reserve(257);
    auto cleanup = barrier::finally([&] { for (int fd : folders) { if (fd >= 0) { ::close(fd); } } });
    // FUTURE(BX-004): macOS extended ACLs need checks beyond these ownership/mode rules.
    const auto check = [](int fd, bool final) {
        struct stat info{};
        if (::fstat(fd, &info) != 0 || !S_ISDIR(info.st_mode)) {
            throw std::runtime_error("Cannot inspect the private storage folder.");
        }
        // FUTURE(BX-007): I want recovery to identify the unsafe ancestor before offering a repair.
        const bool writable = (info.st_mode & (S_IWGRP | S_IWOTH)) != 0;
        const bool shared_root = !final && info.st_uid == 0 && (info.st_mode & S_ISVTX);
        if ((final ? info.st_uid != geteuid() : info.st_uid != 0 && info.st_uid != geteuid()) ||
            (writable && !shared_root)) {
            throw std::runtime_error("The private storage folder chain has unsafe ownership or write access.");
        }
    };
    const int flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
    const int root = ::open("/", flags);
    if (root < 0) { throw std::runtime_error("Cannot open the filesystem root for private storage."); }
    folders.push_back(root);
    check(root, pending.empty());
    unsigned links = 0, steps = 0;
    while (!pending.empty()) {
        if (++steps > 512) { throw std::runtime_error("The private storage folder chain is too complex."); }
        const auto part = pending.front();
        pending.pop_front();
        if (part.name == "..") {
            // Only a checked symlink target can reach this branch.
            if (!part.link_target) { throw std::runtime_error("Invalid private storage traversal."); }
            if (folders.size() > 1) { ::close(folders.back()); folders.pop_back(); }
            continue;
        }
        const bool final = pending.empty();
        struct stat entry{};
        if (::fstatat(folders.back(), part.name.c_str(), &entry, AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno != ENOENT) { throw std::runtime_error("Cannot inspect a private storage ancestor."); }
            if (create) {
                if (::mkdirat(folders.back(), part.name.c_str(), 0700) != 0 && errno != EEXIST) {
                    throw std::runtime_error("Cannot create a private storage folder.");
                }
                if (::fstatat(folders.back(), part.name.c_str(), &entry, AT_SYMLINK_NOFOLLOW) != 0) {
                    throw std::runtime_error("Cannot inspect the created private storage folder.");
                }
            } else if (allow_missing) { return -1; }
            else { throw std::runtime_error("The private storage folder is missing."); }
        }
        if (S_ISLNK(entry.st_mode)) {
            if (final || ++links > 40 || (entry.st_uid != 0 && entry.st_uid != geteuid())) {
                throw std::runtime_error("The private storage folder chain contains an unsupported link.");
            }
            char target[4097];
            const auto length = ::readlinkat(folders.back(), part.name.c_str(), target, sizeof(target));
            if (length <= 0 || length >= static_cast<ssize_t>(sizeof(target))) {
                throw std::runtime_error("Cannot resolve a private storage ancestor link.");
            }
            const barrier::fs::path resolved(std::string(target, static_cast<std::size_t>(length)));
            if (resolved.is_absolute()) {
                while (folders.size() > 1) { ::close(folders.back()); folders.pop_back(); }
            }
            enqueue(resolved, true, true);
            continue;
        }
        int fd = ::openat(folders.back(), part.name.c_str(), flags);
        if (fd < 0) { throw std::runtime_error("Cannot open a private storage ancestor without following links."); }
        auto close_new = barrier::finally([&] { if (fd >= 0) { ::close(fd); } });
        check(fd, final);
        if (folders.size() >= 257) { throw std::runtime_error("The private storage folder chain is too deep."); }
        folders.push_back(fd);
        fd = -1;
    }
    check(folders.back(), true);
    const int result = folders.back();
    folders.back() = -1;
    return result;
}
}
PrivateDirectory::PrivateDirectory(const fs::path& path, PrivateDirectoryMode mode) :
    path_(fs::absolute(path.empty() ? fs::path(".") : path))
{
    descriptor_ = open_private_directory(path_, mode == PrivateDirectoryMode::AllowMissing,
                                         mode == PrivateDirectoryMode::Create);
}
PrivateDirectory::~PrivateDirectory() { if (descriptor_ >= 0) { ::close(descriptor_); } }
void PrivateDirectory::check_current() const
{
    PrivateDirectory current(path_);
    struct stat held{}, reopened{};
    if (::fstat(descriptor_, &held) != 0 || ::fstat(current.descriptor(), &reopened) != 0 ||
        held.st_dev != reopened.st_dev || held.st_ino != reopened.st_ino) {
        throw std::runtime_error("The private storage folder changed during access. Retry the operation.");
    }
}
}
#endif
