/*
 * barrier -- mouse and keyboard sharing utility
 * Copyright (C) 2016 Symless
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

#define BARRIER_TEST_ENV

#include "barrier/KeyMap.h"
#include "base/ILogOutputter.h"
#include "base/Log.h"

#include "test/global/gtest.h"
#include "test/global/gmock.h"

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::SaveArg;

namespace barrier {

TEST(KeyMapTests, findBestKey_requiredDown_matchExactFirstItem)
{
    KeyMap keyMap;
    KeyMap::KeyEntryList entryList;
    KeyMap::KeyItemList itemList;
    KeyMap::KeyItem item;
    item.m_required = KeyModifierShift;
    item.m_sensitive = KeyModifierShift;
    KeyModifierMask currentState = KeyModifierShift;
    KeyModifierMask desiredState = KeyModifierShift;
    itemList.push_back(item);
    entryList.push_back(itemList);

    EXPECT_EQ(0, keyMap.findBestKey(entryList, currentState, desiredState));
}

TEST(KeyMapTests, findBestKey_requiredAndExtraSensitiveDown_matchExactFirstItem)
{
    KeyMap keyMap;
    KeyMap::KeyEntryList entryList;
    KeyMap::KeyItemList itemList;
    KeyMap::KeyItem item;
    item.m_required = KeyModifierShift;
    item.m_sensitive = KeyModifierShift | KeyModifierAlt;
    KeyModifierMask currentState = KeyModifierShift;
    KeyModifierMask desiredState = KeyModifierShift;
    itemList.push_back(item);
    entryList.push_back(itemList);

    EXPECT_EQ(0, keyMap.findBestKey(entryList, currentState, desiredState));
}

TEST(KeyMapTests, findBestKey_requiredAndExtraSensitiveDown_matchExactSecondItem)
{
    KeyMap keyMap;
    KeyMap::KeyEntryList entryList;
    KeyMap::KeyItemList itemList1;
    KeyMap::KeyItem item1;
    item1.m_required = KeyModifierAlt;
    item1.m_sensitive = KeyModifierShift | KeyModifierAlt;
    KeyMap::KeyItemList itemList2;
    KeyMap::KeyItem item2;
    item2.m_required = KeyModifierShift;
    item2.m_sensitive = KeyModifierShift | KeyModifierAlt;
    KeyModifierMask currentState = KeyModifierShift;
    KeyModifierMask desiredState = KeyModifierShift;
    itemList1.push_back(item1);
    itemList2.push_back(item2);
    entryList.push_back(itemList1);
    entryList.push_back(itemList2);

    EXPECT_EQ(1, keyMap.findBestKey(entryList, currentState, desiredState));
}

TEST(KeyMapTests, findBestKey_extraSensitiveDown_matchExactSecondItem)
{
    KeyMap keyMap;
    KeyMap::KeyEntryList entryList;
    KeyMap::KeyItemList itemList1;
    KeyMap::KeyItem item1;
    item1.m_required = 0;
    item1.m_sensitive = KeyModifierAlt;
    KeyMap::KeyItemList itemList2;
    KeyMap::KeyItem item2;
    item2.m_required = 0;
    item2.m_sensitive = KeyModifierShift;
    KeyModifierMask currentState = KeyModifierAlt;
    KeyModifierMask desiredState = KeyModifierAlt;
    itemList1.push_back(item1);
    itemList2.push_back(item2);
    entryList.push_back(itemList1);
    entryList.push_back(itemList2);

    EXPECT_EQ(1, keyMap.findBestKey(entryList, currentState, desiredState));
}

TEST(KeyMapTests, findBestKey_noRequiredDown_matchOneRequiredChangeItem)
{
    KeyMap keyMap;
    KeyMap::KeyEntryList entryList;
    KeyMap::KeyItemList itemList1;
    KeyMap::KeyItem item1;
    item1.m_required = KeyModifierShift | KeyModifierAlt;
    item1.m_sensitive = KeyModifierShift | KeyModifierAlt;
    KeyMap::KeyItemList itemList2;
    KeyMap::KeyItem item2;
    item2.m_required = KeyModifierShift;
    item2.m_sensitive = KeyModifierShift | KeyModifierAlt;
    KeyModifierMask currentState = 0;
    KeyModifierMask desiredState = 0;
    itemList1.push_back(item1);
    itemList2.push_back(item2);
    entryList.push_back(itemList1);
    entryList.push_back(itemList2);

    EXPECT_EQ(1, keyMap.findBestKey(entryList, currentState, desiredState));
}

TEST(KeyMapTests, findBestKey_onlyOneRequiredDown_matchTwoRequiredChangesItem)
{
    KeyMap keyMap;
    KeyMap::KeyEntryList entryList;
    KeyMap::KeyItemList itemList1;
    KeyMap::KeyItem item1;
    item1.m_required = KeyModifierShift | KeyModifierAlt | KeyModifierControl;
    item1.m_sensitive = KeyModifierShift | KeyModifierAlt | KeyModifierControl;
    KeyMap::KeyItemList itemList2;
    KeyMap::KeyItem item2;
    item2.m_required = KeyModifierShift| KeyModifierAlt;
    item2.m_sensitive = KeyModifierShift | KeyModifierAlt | KeyModifierControl;
    KeyModifierMask currentState = 0;
    KeyModifierMask desiredState = 0;
    itemList1.push_back(item1);
    itemList2.push_back(item2);
    entryList.push_back(itemList1);
    entryList.push_back(itemList2);

    EXPECT_EQ(1, keyMap.findBestKey(entryList, currentState, desiredState));
}

TEST(KeyMapTests, findBestKey_noRequiredDown_cannotMatch)
{
    KeyMap keyMap;
    KeyMap::KeyEntryList entryList;
    KeyMap::KeyItemList itemList;
    KeyMap::KeyItem item;
    item.m_required = 0xffffffff;
    item.m_sensitive = 0xffffffff;
    KeyModifierMask currentState = 0;
    KeyModifierMask desiredState = 0;
    itemList.push_back(item);
    entryList.push_back(itemList);

    EXPECT_EQ(-1, keyMap.findBestKey(entryList, currentState, desiredState));
}

TEST(KeyMapTests, isCommand_shiftMask_returnFalse)
{
    KeyMap keyMap;
    KeyModifierMask mask= KeyModifierShift;

    EXPECT_FALSE(keyMap.isCommand(mask));
}

TEST(KeyMapTests, isCommand_controlMask_returnTrue)
{
    KeyMap keyMap;
    KeyModifierMask mask= KeyModifierControl;

    EXPECT_EQ(true, keyMap.isCommand(mask));
}

TEST(KeyMapTests, isCommand_alternateMask_returnTrue)
{
    KeyMap keyMap;
    KeyModifierMask mask= KeyModifierAlt;

    EXPECT_EQ(true, keyMap.isCommand(mask));
}

TEST(KeyMapTests, isCommand_alternateGraphicMask_returnTrue)
{
    KeyMap keyMap;
    KeyModifierMask mask= KeyModifierAltGr;

    EXPECT_EQ(true, keyMap.isCommand(mask));
}

TEST(KeyMapTests, isCommand_metaMask_returnTrue)
{
    KeyMap keyMap;
    KeyModifierMask mask= KeyModifierMeta;

    EXPECT_EQ(true, keyMap.isCommand(mask));
}

TEST(KeyMapTests, isCommand_superMask_returnTrue)
{
    KeyMap keyMap;
    KeyModifierMask mask= KeyModifierSuper;

    EXPECT_EQ(true, keyMap.isCommand(mask));
}

}

namespace {
class InputLogCapture : public ILogOutputter {
public:
    InputLogCapture() : previous(Log::getInstance()->getFilter()) {
        Log::getInstance()->setFilter(kDEBUG5);
        Log::getInstance()->insert(this, true);
    }
    ~InputLogCapture() override {
        Log::getInstance()->remove(this);
        Log::getInstance()->setFilter(previous);
    }
    void open(const char*) override {}
    void close() override {}
    void show(bool) override {}
    bool write(ELevel, const char* message) override {
        const std::string text(message);
        const auto stamp = text.find("] ");
        messages += stamp == std::string::npos ? text : text.substr(stamp + 2);
        return true;
    }
    std::string messages;
private:
    int previous;
};
}

TEST(KeyMapTests, DifferentCharactersKeepTheirValuesOutOfDiagnostics)
{
    barrier::KeyMap map;
    for (auto key : {'a', 'z'}) {
        barrier::KeyMap::KeyItem item{};
        item.m_id = key;
        item.m_button = key;
        map.addKeyEntry(item);
    }
    map.finish();
    InputLogCapture capture;
    const auto exercise = [&](KeyID key) {
        capture.messages.clear();
        barrier::KeyMap::Keystrokes strokes;
        barrier::KeyMap::ModifierToKeys modifiers;
        KeyModifierMask state = 0;
        const auto* result = map.mapKey(strokes, key, 0, modifiers, state, 0, false);
        EXPECT_NE(nullptr, result);
        EXPECT_FALSE(strokes.empty());
        return capture.messages;
    };
    const auto first = exercise('a');
    const auto second = exercise('z');
    EXPECT_FALSE(first.empty());
    EXPECT_EQ(first, second);
    EXPECT_EQ(std::string::npos, first.find("0061"));
    EXPECT_EQ(std::string::npos, second.find("007a"));
}
