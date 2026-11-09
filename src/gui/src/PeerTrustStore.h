/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#pragma once
#include "net/FingerprintDatabase.h"

namespace PeerTrustStore {
// Missing stores are empty; unreadable or unsafe existing stores are errors.
barrier::FingerprintDatabase read(const barrier::fs::path& path);
// Merge under the shared GUI lock; return only after checked publication.
void approve(const barrier::fs::path& path, const barrier::FingerprintData& peer);
}
