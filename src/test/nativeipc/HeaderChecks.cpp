/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#define BARRIER_TEST_ENV
#include "ipc/IpcServer.h"
#include "ipc/IpcClient.h"
void checkNativeHeaderLifetimes() { IpcServer server; }
