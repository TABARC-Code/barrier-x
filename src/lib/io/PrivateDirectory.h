/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#pragma once
#ifndef _WIN32
#include "io/filesystem.h"
namespace barrier {
enum class PrivateDirectoryMode { Existing, AllowMissing, Create };
class PrivateDirectory {
public:
    explicit PrivateDirectory(const fs::path& path,
                              PrivateDirectoryMode mode = PrivateDirectoryMode::Existing);
    ~PrivateDirectory();
    PrivateDirectory(const PrivateDirectory&) = delete;
    PrivateDirectory& operator=(const PrivateDirectory&) = delete;
    // I retain ownership; callers borrow this descriptor for relative operations.
    int descriptor() const { return descriptor_; }
    void check_current() const;
private:
    fs::path path_;
    int descriptor_ = -1;
};
}
#endif
