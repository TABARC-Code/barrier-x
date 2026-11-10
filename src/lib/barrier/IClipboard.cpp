/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2004 Chris Schoeneman
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

#include "barrier/IClipboard.h"
#include "common/stdvector.h"
#include "barrier/XBarrier.h"
#include "base/finally.h"
#include <array>

//
// IClipboard
//

void
IClipboard::unmarshall(IClipboard* clipboard, const String& data, Time time)
{
    assert(clipboard != NULL);

    if (data.size() < 4) {
        throw XBadClient("Clipboard header is truncated");
    }
    const UInt32 numFormats = readUInt32(data.data());
    if (numFormats > (data.size() - 4) / 8) {
        throw XBadClient("Clipboard format count exceeds the message");
    }

    // I check the whole blob before touching the clipboard. Rain or shine.
    std::array<String, kNumFormats> decoded;
    std::array<bool, kNumFormats> present{};
    std::size_t offset = 4;
    for (UInt32 i = 0; i < numFormats; ++i) {
        if (data.size() - offset < 8) {
            throw XBadClient("Clipboard format header is truncated");
        }
        const UInt32 format = readUInt32(data.data() + offset);
        const UInt32 size = readUInt32(data.data() + offset + 4);
        offset += 8;
        if (size > data.size() - offset) {
            throw XBadClient("Clipboard format exceeds the message");
        }
        // Keep wire IDs unsigned; a future format mustn't become a negative index.
        if (format < static_cast<UInt32>(kNumFormats)) {
            decoded[format].assign(data.data() + offset, size);
            present[format] = true;
        }
        offset += size;
    }
    if (offset != data.size()) {
        throw XBadClient("Clipboard message has trailing data");
    }

    if (clipboard->open(time)) {
        auto close = barrier::finally([&] { clipboard->close(); });
        if (!clipboard->empty()) { return; }
        for (UInt32 format = 0; format < static_cast<UInt32>(kNumFormats); ++format) {
            if (present[format]) {
                clipboard->add(static_cast<EFormat>(format), decoded[format]);
            }
        }
    }
}

String
IClipboard::marshall(const IClipboard* clipboard)
{
    // return data format:
    // 4 bytes => number of formats included
    // 4 bytes => format enum
    // 4 bytes => clipboard data size n
    // n bytes => clipboard data
    // back to the second 4 bytes if there is another format

    assert(clipboard != NULL);

    String data;

    std::vector<String> formatData;
    formatData.resize(IClipboard::kNumFormats);
    // FIXME -- use current time
    if (clipboard->open(0)) {

        // compute size of marshalled data
        UInt32 size = 4;
        UInt32 numFormats = 0;
        for (UInt32 format = 0; format != IClipboard::kNumFormats; ++format) {
            if (clipboard->has(static_cast<IClipboard::EFormat>(format))) {
                ++numFormats;
                formatData[format] =
                    clipboard->get(static_cast<IClipboard::EFormat>(format));
                size += 4 + 4 + (UInt32)formatData[format].size();
            }
        }

        // allocate space
        data.reserve(size);

        // marshall the data
        writeUInt32(&data, numFormats);
        for (UInt32 format = 0; format != IClipboard::kNumFormats; ++format) {
            if (clipboard->has(static_cast<IClipboard::EFormat>(format))) {
                writeUInt32(&data, format);
                writeUInt32(&data, (UInt32)formatData[format].size());
                data += formatData[format];
            }
        }
        clipboard->close();
    }

    return data;
}

bool
IClipboard::copy(IClipboard* dst, const IClipboard* src)
{
    assert(dst != NULL);
    assert(src != NULL);

    return copy(dst, src, src->getTime());
}

bool
IClipboard::copy(IClipboard* dst, const IClipboard* src, Time time)
{
    assert(dst != NULL);
    assert(src != NULL);

    bool success = false;
    if (src->open(time)) {
        if (dst->open(time)) {
            if (dst->empty()) {
                for (SInt32 format = 0;
                                format != IClipboard::kNumFormats; ++format) {
                    IClipboard::EFormat eFormat = (IClipboard::EFormat)format;
                    if (src->has(eFormat)) {
                        dst->add(eFormat, src->get(eFormat));
                    }
                }
                success = true;
            }
            dst->close();
        }
        src->close();
    }

    return success;
}

UInt32
IClipboard::readUInt32(const char* buf)
{
    const unsigned char* ubuf = reinterpret_cast<const unsigned char*>(buf);
    return    (static_cast<UInt32>(ubuf[0]) << 24) |
            (static_cast<UInt32>(ubuf[1]) << 16) |
            (static_cast<UInt32>(ubuf[2]) <<  8) |
             static_cast<UInt32>(ubuf[3]);
}

void
IClipboard::writeUInt32(String* buf, UInt32 v)
{
    *buf += static_cast<UInt8>((v >> 24) & 0xff);
    *buf += static_cast<UInt8>((v >> 16) & 0xff);
    *buf += static_cast<UInt8>((v >>  8) & 0xff);
    *buf += static_cast<UInt8>( v        & 0xff);
}
