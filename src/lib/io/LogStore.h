/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#pragma once
#include "io/filesystem.h"
#include <ctime>
#include <string>
namespace barrier {
bool valid_log_retention(int days);
// Only the configured log and its .1 backup are eligible. Errors are reported to the caller.
void append_log(const fs::path& path, const std::string& message, int days, std::time_t now);
unsigned clear_logs(const fs::path& path);
unsigned expire_logs(const fs::path& path, int days, std::time_t now);
}
