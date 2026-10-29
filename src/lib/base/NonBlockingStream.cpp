/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2008 Debauchee Open Source Group
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

#if !defined(_WIN32)

#include "base/NonBlockingStream.h"

#include <unistd.h> // tcgetattr/tcsetattr, read
#include <termios.h> // tcgetattr/tcsetattr
#include <fcntl.h>
#include <errno.h>

NonBlockingStream::NonBlockingStream(int fd) :
    _fd(fd),
    _p_ta_previous(nullptr),
    _cntl_previous(-1)
{
    // disable ICANON & ECHO so we don't have to wait for a newline
    // before we get data (and to keep it from being echoed back out)
    termios ta{};
    // A service or test runner may have a pipe or /dev/null for stdin.
    if (tcgetattr(fd, &ta) == 0) {
        _p_ta_previous = new termios(ta);
        ta.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(fd, TCSANOW, &ta);
    }

    // prevent IO from blocking so we can poll (read())
    _cntl_previous = fcntl(fd, F_GETFL);
    if (_cntl_previous != -1 && fcntl(fd, F_SETFL, _cntl_previous | O_NONBLOCK) == -1) {
        _cntl_previous = -1;
    }
}

NonBlockingStream::~NonBlockingStream()
{
    if (_p_ta_previous) {
        tcsetattr(_fd, TCSANOW, _p_ta_previous);
    }
    if (_cntl_previous != -1) {
        fcntl(_fd, F_SETFL, _cntl_previous);
    }
    delete _p_ta_previous;
}

bool NonBlockingStream::try_read_char(char &ch) const
{
    if (_cntl_previous == -1) {
        return false;
    }
    ssize_t result;
    do {
        result = read(_fd, &ch, 1);
    } while (result == -1 && errno == EINTR);
    // EOF is normal for a detached process. It is not an assertion failure.
    return result == 1;
}

#endif // !defined(_WIN32)
