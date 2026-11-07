/* Copyright (C) 2026 barrier-x contributors
 * Distributed under the GNU General Public License; see LICENSE. */
#include "../src/QBarrierApplication.h"
#include <gtest/gtest.h>
int main(int argc, char** argv)
{
    QBarrierApplication application(argc, argv);
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
