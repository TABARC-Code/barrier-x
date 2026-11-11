/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#pragma once
#ifdef _WIN32
#include <string>
namespace barrier {
// The returned CRT descriptor owns the checked, non-inheritable file handle.
int create_private_file(const std::wstring& path);
int read_private_file(const std::wstring& path);
// Exclusive checked editing for bounded application logs.
int edit_private_log(const std::wstring& path);
// Callers serialise updates. Existing parent directories are checked and must
// not be reparse points or writable by another local principal.
void replace_private_file(const std::wstring& path, const std::string& bytes);
}
#endif
