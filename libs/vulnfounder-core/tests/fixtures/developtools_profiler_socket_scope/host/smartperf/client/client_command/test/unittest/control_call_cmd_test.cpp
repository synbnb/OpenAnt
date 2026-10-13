/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "unistd.h"
#include <thread>
#include <cstdio>
#include <cstring>
#include <map>
#include <sstream>
#include <iomanip>
#include <future>
#include "control_call_cmd.h"
#include "startup_delay.h"
#include "sp_utils.h"
#include "parse_click_complete_trace.h"
#include "parse_click_response_trace.h"
#include "parse_radar.h"
#include "parse_slide_fps_trace.h"
#include "sp_log.h"
#include "stalling_rate_trace.h"
#include "common.h"


using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class ControlCallCmdTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() {}
    void TearDown() {}

    bool isOhTest = false;
    double time = 0.0;
    double noNameType = -1.0;
};

HWTEST_F(ControlCallCmdTest, GetResultTest01, TestSize.Level1)
{
    ControlCallCmd cmd;
    time = cmd.ResponseTime();
    std::vector<std::string> v = {"responseTime"};
    EXPECT_EQ("", cmd.GetResult(v));
}

HWTEST_F(ControlCallCmdTest, GetResultTest02, TestSize.Level1)
{
    ControlCallCmd cmd;
    std::vector<std::string> v = {"completeTime"};
    time = cmd.CompleteTime();
    EXPECT_EQ("", cmd.GetResult(v));
}

HWTEST_F(ControlCallCmdTest, GetResultTest03, TestSize.Level1)
{
    ControlCallCmd cmd;
    std::vector<std::string> v = {"frameLoss"};
    EXPECT_EQ("", cmd.GetResult(v));
}

HWTEST_F(ControlCallCmdTest, GetResultTest04, TestSize.Level1)
{
    ControlCallCmd cmd;
    std::vector<std::string> v = {"appStartTime"};
    EXPECT_EQ("", cmd.GetResult(v));
}

HWTEST_F(ControlCallCmdTest, GetResultTest05, TestSize.Level1)
{
    ControlCallCmd cmd;
    std::vector<std::string> v = {"slideList"};
    EXPECT_EQ("", cmd.GetResult(v));
}

HWTEST_F(ControlCallCmdTest, GetResultTest06, TestSize.Level1)
{
    ControlCallCmd cmd;
    std::vector<std::string> v = {"timeDelay"};
    EXPECT_EQ("", cmd.GetResult(v));
}

HWTEST_F(ControlCallCmdTest, TimeDelayTest01, TestSize.Level1)
{
    OHOS::SmartPerf::ControlCallCmd controlCallCmd;
    std::string expected = "ResponseTime:-1ms\nCompleteTime:-1ms\nHitchTimeRate:0.00ms/s ";
    std::string expectedResult = expected + "\nMAX_RENDER_SEQ_MISSED_FRAMES:-1";
    EXPECT_EQ(controlCallCmd.TimeDelay(), expectedResult);
}

HWTEST_F(ControlCallCmdTest, SlideListTest01, TestSize.Level1)
{
    OHOS::SmartPerf::ControlCallCmd controlCallCmd;
    std::string expected = "FPS:-1fps\nResponseTime:-1ms\nHitchTimeRate:0.00ms/s ";
    std::string expectedResult = expected + "\nMAX_RENDER_SEQ_MISSED_FRAMES:-1";
    std::string resultStream = controlCallCmd.SlideList();
    EXPECT_EQ(resultStream, expectedResult);
}

HWTEST_F(ControlCallCmdTest, GetFrameTest01, TestSize.Level1)
{
    OHOS::SmartPerf::ControlCallCmd controlCallCmd;
    std::string result = controlCallCmd.GetFrame();
    EXPECT_EQ(result, "");
}

HWTEST_F(ControlCallCmdTest, ResponseTimeTest01, TestSize.Level1)
{
    OHOS::SmartPerf::ControlCallCmd controlCallCmd;
    EXPECT_DOUBLE_EQ(controlCallCmd.ResponseTime(), -1);
}

HWTEST_F(ControlCallCmdTest, CompleteTimeTest01, TestSize.Level1)
{
    OHOS::SmartPerf::ControlCallCmd cmd;
    double expectedTime = -1;
    double result = cmd.CompleteTime();
    EXPECT_EQ(result, expectedTime);
}

HWTEST_F(ControlCallCmdTest, IsohTest01, TestSize.Level1)
{
    OHOS::SmartPerf::ControlCallCmd controlCallCmd;
    bool isOhTest = true;
    std::vector<std::string> v = {"", "", "ohtest"};
    controlCallCmd.IsohTest(v);
    ASSERT_TRUE(isOhTest);
}

HWTEST_F(ControlCallCmdTest, IsohTest02, TestSize.Level1)
{
    OHOS::SmartPerf::ControlCallCmd controlCallCmd;
    bool isOhTest = false;
    std::vector<std::string> v = {"", "", "notohtest"};
    controlCallCmd.IsohTest(v);
    ASSERT_FALSE(isOhTest);
}
}
}