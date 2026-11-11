/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2002 Chris Schoeneman
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 *
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "base/log_outputters.h"
#include "arch/Arch.h"
#include "base/String.h"
#include "io/filesystem.h"
#include "io/LogStore.h"
#include <chrono>
#include <ctime>
#include <cstdio>
#include <stdexcept>


//
// StopLogOutputter
//

StopLogOutputter::StopLogOutputter()
{
    // do nothing
}

StopLogOutputter::~StopLogOutputter()
{
    // do nothing
}

void
StopLogOutputter::open(const char*)
{
    // do nothing
}

void
StopLogOutputter::close()
{
    // do nothing
}

void
StopLogOutputter::show(bool)
{
    // do nothing
}

bool
StopLogOutputter::write(ELevel, const char*)
{
    return false;
}


//
// ConsoleLogOutputter
//

ConsoleLogOutputter::ConsoleLogOutputter()
{
}

ConsoleLogOutputter::~ConsoleLogOutputter()
{
}

void
ConsoleLogOutputter::open(const char* title)
{
    ARCH->openConsole(title);
}

void
ConsoleLogOutputter::close()
{
    ARCH->closeConsole();
}

void
ConsoleLogOutputter::show(bool showIfEmpty)
{
    ARCH->showConsole(showIfEmpty);
}

bool
ConsoleLogOutputter::write(ELevel level, const char* msg)
{
    ARCH->writeConsole(level, msg);
    return true;
}

void
ConsoleLogOutputter::flush()
{

}


//
// SystemLogOutputter
//

SystemLogOutputter::SystemLogOutputter()
{
    // do nothing
}

SystemLogOutputter::~SystemLogOutputter()
{
    // do nothing
}

void
SystemLogOutputter::open(const char* title)
{
    ARCH->openLog(title);
}

void
SystemLogOutputter::close()
{
    ARCH->closeLog();
}

void
SystemLogOutputter::show(bool showIfEmpty)
{
    ARCH->showLog(showIfEmpty);
}

bool
SystemLogOutputter::write(ELevel level, const char* msg)
{
    ARCH->writeLog(level, msg);
    return true;
}

//
// SystemLogger
//

SystemLogger::SystemLogger(const char* title, bool blockConsole) :
    m_stop(NULL)
{
    // redirect log messages
    if (blockConsole) {
        m_stop = new StopLogOutputter;
        CLOG->insert(m_stop);
    }
    m_syslog = new SystemLogOutputter;
    m_syslog->open(title);
    CLOG->insert(m_syslog);
}

SystemLogger::~SystemLogger()
{
    CLOG->remove(m_syslog);
    delete m_syslog;
    if (m_stop != NULL) {
        CLOG->remove(m_stop);
        delete m_stop;
    }
}


//
// BufferedLogOutputter
//

BufferedLogOutputter::BufferedLogOutputter(UInt32 maxBufferSize) :
    m_maxBufferSize(maxBufferSize)
{
    // do nothing
}

BufferedLogOutputter::~BufferedLogOutputter()
{
    // do nothing
}

BufferedLogOutputter::const_iterator
BufferedLogOutputter::begin() const
{
    return m_buffer.begin();
}

BufferedLogOutputter::const_iterator
BufferedLogOutputter::end() const
{
    return m_buffer.end();
}

void
BufferedLogOutputter::open(const char*)
{
    // do nothing
}

void
BufferedLogOutputter::close()
{
    // remove all elements from the buffer
    m_buffer.clear();
}

void
BufferedLogOutputter::show(bool)
{
    // do nothing
}

bool
BufferedLogOutputter::write(ELevel, const char* message)
{
    while (m_buffer.size() >= m_maxBufferSize) {
        m_buffer.pop_front();
    }
    m_buffer.push_back(std::string(message));
    return true;
}


//
// FileLogOutputter
//

FileLogOutputter::FileLogOutputter(const char* logFile, int retentionDays) :
    m_retentionDays(retentionDays)
{
    if (!barrier::valid_log_retention(retentionDays)) { throw std::invalid_argument("Invalid log retention"); }
    setLogFilename(logFile);
    if (retentionDays) {
        m_cleanupThread = std::thread([this] {
            std::unique_lock<std::mutex> lock(m_fileMutex);
            do {
                try { barrier::expire_logs(barrier::fs::u8path(m_fileName), m_retentionDays, std::time(nullptr)); }
                catch (const std::exception&) { reportFailure(); }
            } while (!m_changed.wait_for(lock, std::chrono::seconds(60), [this] { return m_stop; }));
        });
    }
}
FileLogOutputter::~FileLogOutputter() { close(); }
void FileLogOutputter::setLogFilename(const char* logFile)
{
    assert(logFile != NULL);
    std::lock_guard<std::mutex> lock(m_fileMutex);
    m_fileName = logFile;
}
void FileLogOutputter::reportFailure()
{
    if (!m_warned) {
        std::fputs("Log file operation failed; check ownership, permissions, file type or another active writer.\n", stderr);
        m_warned = true;
    }
}
bool FileLogOutputter::write(ELevel, const char* message)
{
    if (!message) { return true; }
    std::lock_guard<std::mutex> lock(m_fileMutex);
    try {
        barrier::append_log(barrier::fs::u8path(m_fileName), message, m_retentionDays, std::time(nullptr));
        m_warned = false;
    } catch (const std::exception&) { reportFailure(); }
    return true;
}
void FileLogOutputter::open(const char*) {}
void FileLogOutputter::close()
{
    {
        std::lock_guard<std::mutex> lock(m_fileMutex);
        m_stop = true;
    }
    m_changed.notify_all();
    if (m_cleanupThread.joinable()) { m_cleanupThread.join(); }
}
void FileLogOutputter::show(bool) {}

//
// MesssageBoxLogOutputter
//

MesssageBoxLogOutputter::MesssageBoxLogOutputter()
{
    // do nothing
}

MesssageBoxLogOutputter::~MesssageBoxLogOutputter()
{
    // do nothing
}

void
MesssageBoxLogOutputter::open(const char* title)
{
    // do nothing
}

void
MesssageBoxLogOutputter::close()
{
    // do nothing
}

void
MesssageBoxLogOutputter::show(bool showIfEmpty)
{
    // do nothing
}

bool
MesssageBoxLogOutputter::write(ELevel level, const char* msg)
{
    // don't spam user with messages.
    if (level > kERROR) {
        return true;
    }

#if SYSAPI_WIN32
    MessageBox(NULL, msg, CLOG->getFilterName(level), MB_OK);
#endif

    return true;
}
