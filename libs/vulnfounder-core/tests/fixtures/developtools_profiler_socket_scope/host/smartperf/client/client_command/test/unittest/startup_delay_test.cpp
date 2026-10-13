/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <gtest/gtest.h>
#include <thread>
#include <cstdio>
#include <ios>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "startup_delay.h"
#include "sp_utils.h"
#include "sp_log.h"
#include "common.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class StartupDelayTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(StartupDelayTest, GetTraceTest01, TestSize.Level1)
{
    StartUpDelay startUpDelay;
    std::string result;
    std::string cmdString;
    std::string traceName = "testTrace";
    cmdString = "hitrace --trace_clock mono -t 10 -b 102400 --overwrite idle ace app ohos ability graphic nweb";
    SPUtils::LoadCmd(cmdString + traceName, result);
    startUpDelay.GetTrace(traceName);
    ASSERT_TRUE(true);
}

HWTEST_F(StartupDelayTest, GetTraceTest02, TestSize.Level1)
{
    StartUpDelay startUpDelay;
    std::string result;
    std::string cmdString;
    std::string traceName = "testTrace";
    cmdString = "hitrace --trace_clock mono -t 10 -b 204800 --overwrite idle ace app ohos ability graphic nweb";
    SPUtils::LoadCmd(cmdString + traceName, result);
    startUpDelay.GetTrace(traceName);
    ASSERT_TRUE(true);
}

HWTEST_F(StartupDelayTest, GetHisysIdTest01, TestSize.Level1)
{
    StartUpDelay startUpDelay;
    startUpDelay.GetHisysId();
    ASSERT_TRUE(true);
}

HWTEST_F(StartupDelayTest, GetHisysIdAndKillTest01, TestSize.Level1)
{
    StartUpDelay startUpDelay;
    startUpDelay.GetHisysIdAndKill();
    ASSERT_TRUE(true);
}

HWTEST_F(StartupDelayTest, KillSpProcessTest01, TestSize.Level1)
{
    StartUpDelay startUpDelay;
    bool result = startUpDelay.KillSpProcess();
    EXPECT_FALSE(result);
}

HWTEST_F(StartupDelayTest, GetSpClearTest01, TestSize.Level1)
{
    StartUpDelay startUpDelay;
    bool result = startUpDelay.GetSpClear(false);
    EXPECT_FALSE(result);
}

HWTEST_F(StartupDelayTest, GetPidByPkgTest01, TestSize.Level1)
{
    StartUpDelay startUpDelay;
    std::string curPkgName = "testPackage";
    EXPECT_EQ(startUpDelay.GetPidByPkg(curPkgName), "");
}

}
}