/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#pragma once
#ifdef _WIN32
#include <string>
namespace barrier {
// The returned CRT descriptor owns the checked, non-inheritable file handle.
int create_private_file(const std::wstring& path);
int read_private_file(const std::wstring& path);
// Callers serialise updates. Parent directories must still be trusted.
void replace_private_file(const std::wstring& path, const std::string& bytes);
}
#endif
