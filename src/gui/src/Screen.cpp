/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2008 Volker Lanz (vl@fidra.de)
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

#include "Screen.h"

#include <QtCore>
#include <QtGui>

Screen::Screen() :
    m_Pixmap(QPixmap(":res/icons/64x64/video-display.png")),
    m_Swapped(false)
{
    init();
}

Screen::Screen(const QString& name) :
    m_Pixmap(QPixmap(":res/icons/64x64/video-display.png")),
    m_Swapped(false)
{
    init();
    setName(name);
}

void Screen::init()
{
    name().clear();
    aliases().clear();
    modifiers().clear();
    switchCorners().clear();
    fixes().clear();
    setSwitchCornerSize(0);

    // m_Modifiers, m_SwitchCorners and m_Fixes are QLists we use like fixed-size arrays,
    // thus we need to make sure to fill them with the required number of elements.
    for (int i = 0; i < static_cast<int>(Modifier::Count); i++)
        modifiers() << static_cast<Modifier>(i);

    for (int i = 0; i < static_cast<int>(SwitchCorner::Count); i++)
        switchCorners() << false;

    for (int i = 0; i < static_cast<int>(Fix::Count); i++)
        fixes() << false;
}

void Screen::loadSettings(QSettings& settings)
{
    setName(settings.value("name").toString());

    if (name().isEmpty())
        return;

    setSwitchCornerSize(settings.value("switchCornerSize").toInt());

    readSettings<QString>(settings, aliases(), "alias", QString(""));
    readSettings<int>(settings, modifiers(), "modifier", Modifier::DefaultMod,
                      static_cast<int>(Modifier::Count));
    readSettings<bool>(settings, switchCorners(), "switchCorner", false,
                       static_cast<int>(SwitchCorner::Count));
    readSettings<bool>(settings, fixes(), "fix", false, static_cast<int>(Fix::Count));
}

void Screen::saveSettings(QSettings& settings) const
{
    settings.setValue("name", name());

    if (name().isEmpty())
        return;

    settings.setValue("switchCornerSize", switchCornerSize());

    writeSettings<QString>(settings, aliases(), "alias");
    writeSettings<int>(settings, modifiers(), "modifier");
    writeSettings<bool>(settings, switchCorners(), "switchCorner");
    writeSettings<bool>(settings, fixes(), "fix");
}

QTextStream& Screen::writeScreensSection(QTextStream& outStream) const
{
    outStream << "\t" << name() << ":" << Qt::endl;

    for (int i = 0; i < modifiers().size(); i++) {
        auto mod = static_cast<Modifier>(i);
        if (modifier(mod) != mod) {
            outStream << "\t\t" << modifierName(mod) << " = " << modifierName(modifier(mod))
                      << Qt::endl;
        }
    }

    for (int i = 0; i < fixes().size(); i++) {
        auto fix = static_cast<Fix>(i);
        outStream << "\t\t" << fixName(fix) << " = " << (fixes()[i] ? "true" : "false") << Qt::endl;
    }

    outStream << "\t\t" << "switchCorners = none ";
    for (int i = 0; i < switchCorners().size(); i++) {
        if (switchCorners()[i]) {
            outStream << "+" << switchCornerName(static_cast<SwitchCorner>(i)) << " ";
        }
    }
    outStream << Qt::endl;

    outStream << "\t\t" << "switchCornerSize = " << switchCornerSize() << Qt::endl;

    return outStream;
}

QTextStream& Screen::writeAliasesSection(QTextStream& outStream) const
{
    if (!aliases().isEmpty())
    {
        outStream << "\t" << name() << ":" << Qt::endl;

        for (const QString& alias : aliases()) {
            outStream << "\t\t" << alias << Qt::endl;
        }
    }

    return outStream;
}

QDataStream& operator<<(QDataStream& outStream, const Screen& screen)
{
    outStream.setVersion(QDataStream::Qt_5_15);
    QList<int> modifiers;
    for (auto mod : screen.modifiers()) {
        modifiers.push_back(static_cast<int>(mod));
    }

    return outStream
        << screen.name()
        << screen.switchCornerSize()
        << screen.aliases()
        << modifiers
        << screen.switchCorners()
        << screen.fixes()
        ;
}

namespace {
bool validScreenFrame(QDataStream& input)
{
    auto* device = input.device();
    if (!device || device->isSequential()) { return false; }
    const auto position = device->pos();
    QDataStream probe(device);
    probe.setVersion(QDataStream::Qt_5_15);
    probe.setByteOrder(input.byteOrder());
    const auto text = [&]() {
        quint32 length = 0;
        probe >> length;
        if (probe.status() != QDataStream::Ok) { return false; }
        if (length == 0xffffffffu) { return true; }
        return length <= 2048 && !(length & 1) && device->bytesAvailable() >= length &&
            probe.skipRawData(static_cast<int>(length)) == static_cast<int>(length);
    };
    bool valid = text();
    qint32 corner = 0;
    quint32 count = 0;
    if (valid) { probe >> corner >> count; valid = corner >= 0 && corner <= 10000 && count <= 128; }
    for (quint32 i = 0; valid && i < count; ++i) { valid = text(); }
    if (valid) { probe >> count; valid = count == static_cast<quint32>(BaseConfig::Modifier::Count); }
    for (quint32 i = 0; valid && i < count; ++i) {
        qint32 value = 0;
        probe >> value;
        valid = value >= -1 && value < static_cast<int>(BaseConfig::Modifier::Count);
    }
    for (auto expected : {static_cast<quint32>(BaseConfig::SwitchCorner::Count),
                          static_cast<quint32>(BaseConfig::Fix::Count)}) {
        if (valid) { probe >> count; valid = count == expected; }
        for (quint32 i = 0; valid && i < count; ++i) {
            quint8 value = 0;
            probe >> value;
            valid = value <= 1;
        }
    }
    const bool rewound = device->seek(position);
    return valid && probe.status() == QDataStream::Ok && rewound;
}
}

QDataStream& operator>>(QDataStream& inStream, Screen& screen)
{
    inStream.setVersion(QDataStream::Qt_5_15);
    // I check collection lengths before Qt allocates them. Drag data comes from other processes too.
    if (!validScreenFrame(inStream)) {
        inStream.setStatus(QDataStream::ReadCorruptData);
        return inStream;
    }
    Screen candidate;
    QList<int> modifiers;
    inStream >> candidate.m_Name >> candidate.m_SwitchCornerSize >> candidate.m_Aliases
             >> modifiers >> candidate.m_SwitchCorners >> candidate.m_Fixes;
    const QRegularExpression identifier(QStringLiteral("\\A[A-Za-z0-9._-]{1,255}\\z"));
    // I validate here too: another process doesn't have to use our name editor.
    const auto safeName = [&](const QString& name) { return identifier.match(name).hasMatch(); };
    bool validNames = safeName(candidate.m_Name);
    for (const auto& alias : candidate.m_Aliases) { validNames = validNames && safeName(alias); }
    if (inStream.status() != QDataStream::Ok || !validNames) {
        inStream.setStatus(QDataStream::ReadCorruptData);
        return inStream;
    }
    candidate.m_Modifiers.clear();
    for (auto mod : modifiers) { candidate.m_Modifiers.push_back(static_cast<Screen::Modifier>(mod)); }
    screen = candidate;
    return inStream;
}
