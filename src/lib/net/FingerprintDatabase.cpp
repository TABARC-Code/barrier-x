/*
    barrier -- mouse and keyboard sharing utility
    Copyright (C) Barrier contributors

    This package is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    found in the file LICENSE that should have accompanied this file.

    This package is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "base/String.h"
#include "FingerprintDatabase.h"
#include "io/filesystem.h"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cerrno>
#include <utility>
#include <system_error>
#include "base/finally.h"
#ifdef _WIN32
#include "io/WinPrivateFile.h"
#include <io.h>
#else
#include "io/PrivateDirectory.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace barrier {

void FingerprintDatabase::read(const fs::path& path)
{
    std::ifstream file;
    open_utf8_path(file, path, std::ios_base::in);
    read_stream(file);
}

void FingerprintDatabase::read_trusted(const fs::path& path)
{
    // I don't let an unreadable replacement leave yesterday's approvals active.
    fingerprints_.clear();
    constexpr std::size_t limit = 1024 * 1024;
    int descriptor = -1;
#ifdef _WIN32
    std::error_code error;
    const auto status = fs::symlink_status(path, error);
    if (error == std::errc::no_such_file_or_directory || (!error && !fs::exists(status))) { return; }
    if (error) { throw std::runtime_error("Cannot inspect peer trust storage"); }
    descriptor = read_private_file(path.native());
    auto cleanup = finally([&] { _close(descriptor); });
#else
    const auto name = path.filename().native();
    if (path.native().find('\0') != std::string::npos || name.empty() || name == "." || name == "..") {
        throw std::runtime_error("Peer trust storage needs a valid file name");
    }
    PrivateDirectory directory(path.parent_path(), PrivateDirectoryMode::AllowMissing);
    if (directory.descriptor() < 0) { return; }
    descriptor = ::openat(directory.descriptor(), name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        if (errno == ENOENT) { return; }
        throw std::runtime_error("Cannot open peer trust storage");
    }
    auto cleanup = finally([&] { ::close(descriptor); });
    struct stat info{};
    if (::fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != geteuid() ||
        info.st_nlink != 1 || (info.st_mode & (S_IWGRP | S_IWOTH)) != 0 || info.st_size < 0 ||
        static_cast<unsigned long long>(info.st_size) > limit) {
        throw std::runtime_error("Peer trust storage has unsafe ownership, links, access or size");
    }
#endif
    std::string bytes;
    char buffer[4096];
    while (true) {
        const auto wanted = std::min<std::size_t>(sizeof(buffer), limit + 1 - bytes.size());
#ifdef _WIN32
        const auto count = _read(descriptor, buffer, static_cast<unsigned>(wanted));
#else
        const auto count = ::read(descriptor, buffer, wanted);
#endif
        if (count < 0 && errno == EINTR) { continue; }
        if (count < 0) { throw std::runtime_error("Cannot read peer trust storage"); }
        if (count == 0) { break; }
        bytes.append(buffer, static_cast<std::size_t>(count));
        if (bytes.size() > limit) { throw std::runtime_error("Peer trust storage exceeds 1 MiB"); }
    }
#ifndef _WIN32
    directory.check_current();
#endif
    FingerprintDatabase checked;
    std::istringstream encoded(bytes);
    std::string line;
    while (std::getline(encoded, line)) {
        if (!line.empty() && line.back() == '\r') { line.pop_back(); }
        if (line.empty()) { continue; }
        const auto peer = parse_db_line(line);
        if (!((peer.algorithm == "sha256" && peer.data.size() == 32) ||
              (peer.algorithm == "sha1" && peer.data.size() == 20))) {
            throw std::runtime_error("Peer trust storage contains a malformed or unsupported entry");
        }
        checked.add_trusted(peer);
    }
    // FUTURE(BX-002): Windows ancestors and macOS extended ACLs still need review.
    fingerprints_ = std::move(checked.fingerprints_);
}

void FingerprintDatabase::write(const fs::path& path)
{
    std::ofstream file;
    open_utf8_path(file, path, std::ios_base::out);
    write_stream(file);
}

void FingerprintDatabase::read_stream(std::istream& stream)
{
    if (!stream.good()) {
        return;
    }

    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty()) {
            continue;
        }

        auto fingerprint = parse_db_line(line);
        if (!fingerprint.valid()) {
            continue;
        }

        fingerprints_.push_back(fingerprint);
    }
}

void FingerprintDatabase::write_stream(std::ostream& stream)
{
    if (!stream.good()) {
        return;
    }

    for (const auto& fingerprint : fingerprints_) {
        stream << to_db_line(fingerprint) << "\n";
    }
}

void FingerprintDatabase::clear()
{
    fingerprints_.clear();
}

void FingerprintDatabase::add_trusted(const FingerprintData& fingerprint)
{
    if (is_trusted(fingerprint)) {
        return;
    }
    fingerprints_.push_back(fingerprint);
}

bool FingerprintDatabase::is_trusted(const FingerprintData& fingerprint)
{
    auto found_it = std::find(fingerprints_.begin(), fingerprints_.end(), fingerprint);
    return found_it != fingerprints_.end();
}

FingerprintData FingerprintDatabase::parse_db_line(const std::string& line)
{
    FingerprintData result;

    // legacy v1 certificate handling
    if (std::count(line.begin(), line.end(), ':') == 19 && line.size() == 40 + 19) {
        auto data = string::from_hex(line);
        if (data.empty()) {
            return result;
        }
        result.algorithm = fingerprint_type_to_string(FingerprintType::SHA1);
        result.data = data;
        return result;
    }

    auto version_end_pos = line.find(':');
    if (version_end_pos == std::string::npos) {
        return result;
    }
    if (line.substr(0, version_end_pos) != "v2") {
        return result;
    }
    auto algo_start_pos = version_end_pos + 1;
    auto algo_end_pos = line.find(':', algo_start_pos);
    if (algo_end_pos == std::string::npos) {
        return result;
    }
    auto algorithm = line.substr(algo_start_pos, algo_end_pos - algo_start_pos);
    auto data = string::from_hex(line.substr(algo_end_pos + 1));

    if (data.empty()) {
        return result;
    }

    result.algorithm = algorithm;
    result.data = data;
    return result;
}

std::string FingerprintDatabase::to_db_line(const FingerprintData& fingerprint)
{
    return "v2:" + fingerprint.algorithm + ":" + string::to_hex(fingerprint.data, 2);
}

} // namespace barrier
