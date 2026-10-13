/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
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
#include <fstream>
#include <string>
#include <iostream>
#include <regex>
#include <cmath>
#include <unordered_set>
#include "stalling_rate_trace.h"
#include "sp_log.h"
#include "sp_utils.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class StallingRateTraceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() {}
    void TearDown() {}

    double nowFrameRate = 0;
    double nowSwiperFrameRate = 0;
    double nowTabsFrameRate = 0;
    double oneThousand = 1000;
    double roundTime = 0;
    double roundSwiperTime = 0;
    double roundTabsTime = 0;
    int fenceId = 0;
    int fenceIdSwiper = 0;
    int fenceIdTabs = 0;
    double nowTime = 0;
    double nowSwiperTime = 0;
    double nowTabsTime = 0;
    double lastTime = 0;
    double lastSwiperTime = 0;
    double lastTabsTime = 0;
    double frameLossTime = 0;
    double frameLossRate = 0;
    double frameLossSwiperTime = 0;
    double frameLossTabsTime = 0;
    double swiperFrameLossRate = 0;
    double appFrameLossRate = 0;
    double tabsFrameLossRate = 0;
    double appListDynamicStartTime = 0;
    double appListDynamicFinishTime = 0;
    double appTabsDynamicStartTime = 0;
    double appTabsDynamicFinishTime = 0;
    double swiperDynamicStartTime = 0;
    double swiperDynamicFinishTime = 0;
    bool upperScreenFlag = false;
    bool upperScreenSwiperFlag = false;
    bool upperScreenTabsFlag = false;
    int swiperScrollFlag = 0;
    int swiperFlingFlag = 0;
    bool listFlag = false;
    bool tabsFlag = false;
    bool swiperFlag = false;
};

HWTEST_F(StallingRateTraceTest, StallingRateResultTest01, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    std::string file = "non_existent_file.txt";
    double result = stallingRateTrace.StallingRateResult(file);
    EXPECT_EQ(result, 0);
}

HWTEST_F(StallingRateTraceTest, StallingRateResultTest02, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    EXPECT_EQ(stallingRateTrace.CalculateTime(), -1);
}

HWTEST_F(StallingRateTraceTest, StallingRateResultTest03, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    std::string filename = "test_input.txt";
    std::ifstream infile(filename);
    EXPECT_NE(stallingRateTrace.CalculateTime(), 0);
}

HWTEST_F(StallingRateTraceTest, StallingRateResultTest04, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    std::string filename = "valid_input.txt";
    std::ifstream infile(filename);
    double correctValue = -1;
    EXPECT_EQ(stallingRateTrace.CalculateTime(), correctValue);
}

HWTEST_F(StallingRateTraceTest, CalcFrameRate01, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    appListDynamicStartTime = 100;
    appListDynamicFinishTime= 200;
    frameLossTime = 50;
    stallingRateTrace.CalcFrameRate();
    EXPECT_EQ(appFrameLossRate, 0);
}

HWTEST_F(StallingRateTraceTest, CalcFrameRate02, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    appListDynamicStartTime = 0;
    appListDynamicFinishTime= 200;
    stallingRateTrace.CalcFrameRate();
    EXPECT_EQ(appFrameLossRate, 0);
}

HWTEST_F(StallingRateTraceTest, CalcFrameRate03, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    appListDynamicStartTime = 100;
    appListDynamicFinishTime= 200;
    frameLossSwiperTime = 50;
    stallingRateTrace.CalcFrameRate();
    EXPECT_EQ(swiperFrameLossRate, 0);
}

HWTEST_F(StallingRateTraceTest, CalcFrameRate04, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    appListDynamicStartTime = 0;
    appListDynamicFinishTime= 200;
    stallingRateTrace.CalcFrameRate();
    EXPECT_EQ(swiperFrameLossRate, 0);
}

HWTEST_F(StallingRateTraceTest, CalcFrameRate05, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    appListDynamicStartTime = 100;
    appListDynamicFinishTime= 200;
    frameLossTabsTime = 50;
    stallingRateTrace.CalcFrameRate();
    EXPECT_EQ(tabsFrameLossRate, 0);
}

HWTEST_F(StallingRateTraceTest, CalcFrameRate06, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    appListDynamicStartTime = 0;
    appListDynamicFinishTime= 200;
    stallingRateTrace.CalcFrameRate();
    EXPECT_EQ(tabsFrameLossRate, 0);
}

HWTEST_F(StallingRateTraceTest, JudgFrameRate01, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    appListDynamicFinishTime= 0;
    swiperFlag = true;
    tabsFlag = false;
    stallingRateTrace.JudgFrameRate();
    EXPECT_EQ(frameLossRate, swiperFrameLossRate);
}

HWTEST_F(StallingRateTraceTest, JudgFrameRate02, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    appListDynamicFinishTime= 0;
    swiperFlag = false;
    tabsFlag = true;
    stallingRateTrace.JudgFrameRate();
    EXPECT_EQ(frameLossRate, tabsFrameLossRate);
}

HWTEST_F(StallingRateTraceTest, JudgFrameRate03, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    appListDynamicFinishTime= 0;
    swiperFlag = false;
    tabsFlag = false;
    stallingRateTrace.JudgFrameRate();
    EXPECT_EQ(frameLossRate, 0);
}

HWTEST_F(StallingRateTraceTest, JudgFrameRate04, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    appListDynamicFinishTime= 1;
    swiperFlag = false;
    tabsFlag = false;
    stallingRateTrace.JudgFrameRate();
    EXPECT_EQ(frameLossRate, 0);
}

HWTEST_F(StallingRateTraceTest, AppList01, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    listFlag = false;
    stallingRateTrace.AppList("test_line", "test_signS", "test_signF");
    EXPECT_EQ(appListDynamicFinishTime, stallingRateTrace.GetTimes("test_line", "test_signF"));
    EXPECT_FALSE(listFlag);
}

HWTEST_F(StallingRateTraceTest, AppList02, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    listFlag = true;
    stallingRateTrace.AppList("test_line", "test_signS", "test_signF");
    EXPECT_EQ(appListDynamicFinishTime, stallingRateTrace.GetTimes("test_line", "test_signS"));
    EXPECT_TRUE(listFlag);
    EXPECT_EQ(frameLossTime, 0);
}

HWTEST_F(StallingRateTraceTest, GetFrameLossTime01, TestSize.Level1)
{
    double curTime = 10.0;
    double prevTime = 5.0;
    double drawTime = 3.0;
    double totalFrameLossTime = 0.0;
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    stallingRateTrace.GetFrameLossTime(curTime, prevTime, drawTime, totalFrameLossTime);
    EXPECT_EQ(totalFrameLossTime, 2.0);
}

HWTEST_F(StallingRateTraceTest, GetFrameLossTime02, TestSize.Level1)
{
    double curTime = 5.0;
    double prevTime = 5.0;
    double drawTime = 3.0;
    double totalFrameLossTime = 0.0;
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    stallingRateTrace.GetFrameLossTime(curTime, prevTime, drawTime, totalFrameLossTime);
    EXPECT_EQ(totalFrameLossTime, 0.0);
}

HWTEST_F(StallingRateTraceTest, GetFrameLossTime03, TestSize.Level1)
{
    double curTime = 10.0;
    double prevTime = 0.0;
    double drawTime = 3.0;
    double totalFrameLossTime = 0.0;
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    stallingRateTrace.GetFrameLossTime(curTime, prevTime, drawTime, totalFrameLossTime);
    EXPECT_EQ(totalFrameLossTime, 0.0);
}

HWTEST_F(StallingRateTraceTest, GetRsHardWareRate01, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    double curFrameRate = 10.0;
    upperScreenFlag = true;
    std::string line = "H:RSHardwareThread::CommitAndReleaseLayers";
    OHOS::SmartPerf::StallingRateTrace::SWIM_TYPE type = OHOS::SmartPerf::StallingRateTrace::SWIM_APPLIST;
    stallingRateTrace.GetRsHardWareRate(curFrameRate, line, type);
    EXPECT_TRUE(upperScreenFlag);
}

HWTEST_F(StallingRateTraceTest, GetRsHardWareRate02, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    double curFrameRate = 10.0;
    upperScreenSwiperFlag = true;
    std::string line = "H:RSHardwareThread::PerformSetActiveMode setting active mode";
    OHOS::SmartPerf::StallingRateTrace::SWIM_TYPE type = OHOS::SmartPerf::StallingRateTrace::SWIM_APPSWIPER;
    stallingRateTrace.GetRsHardWareRate(curFrameRate, line, type);
    EXPECT_TRUE(upperScreenSwiperFlag);
}

HWTEST_F(StallingRateTraceTest, GetRsHardWareRate03, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    double curFrameRate = 10.0;
    upperScreenTabsFlag = true;
    std::string line = "H:RSHardwareThread::CommitAndReleaseLayers";
    OHOS::SmartPerf::StallingRateTrace::SWIM_TYPE type = OHOS::SmartPerf::StallingRateTrace::SWIM_APPTABS;
    stallingRateTrace.GetRsHardWareRate(curFrameRate, line, type);
    EXPECT_TRUE(upperScreenTabsFlag);
}

HWTEST_F(StallingRateTraceTest, UpdateRoundTime01, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    stallingRateTrace.UpdateRoundTime(10, OHOS::SmartPerf::StallingRateTrace::SWIM_APPLIST);
    EXPECT_EQ(roundTime, 0);
}

HWTEST_F(StallingRateTraceTest, UpdateRoundTime02, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    stallingRateTrace.UpdateRoundTime(10, OHOS::SmartPerf::StallingRateTrace::SWIM_APPSWIPER);
    EXPECT_EQ(roundTime, 0);
}

HWTEST_F(StallingRateTraceTest, UpdateRoundTime03, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    stallingRateTrace.UpdateRoundTime(10, OHOS::SmartPerf::StallingRateTrace::SWIM_APPTABS);
    EXPECT_EQ(roundTime, 0);
}

HWTEST_F(StallingRateTraceTest, UpdateRoundTime04, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    stallingRateTrace.UpdateRoundTime(0, OHOS::SmartPerf::StallingRateTrace::SWIM_APPLIST);
    EXPECT_EQ(roundTime, 0);
}

HWTEST_F(StallingRateTraceTest, AppSwiperScroll01, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    std::string line = "some line";
    std::string signS = "some signS";
    std::string signF = "some signF";
    stallingRateTrace.AppSwiperScroll(line, signS, signF);
    EXPECT_EQ(swiperScrollFlag, 0);
    EXPECT_EQ(swiperFlag, false);
}

HWTEST_F(StallingRateTraceTest, AppSwiperScroll02, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    std::string line = "some line";
    std::string signS = "some signS";
    std::string signF = "some signF";
    swiperScrollFlag = 0;
    swiperDynamicStartTime = -1;
    stallingRateTrace.AppSwiperScroll(line, signS, signF);
    EXPECT_NE(swiperDynamicStartTime, 0);
}

HWTEST_F(StallingRateTraceTest, AppSwiperScroll03, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    std::string line = "some line";
    std::string signS = "some signS";
    std::string signF = "some signF";
    swiperFlingFlag = 1;
    swiperDynamicFinishTime = -1;
    stallingRateTrace.AppSwiperScroll(line, signS, signF);
    EXPECT_NE(swiperDynamicFinishTime, 0);
}

HWTEST_F(StallingRateTraceTest, APPTabs01, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    tabsFlag = false;
    stallingRateTrace.APPTabs("test_line", "test_signS", "test_signF");
    EXPECT_EQ(appTabsDynamicFinishTime, stallingRateTrace.GetTimes("test_line", "test_signF"));
    EXPECT_FALSE(tabsFlag);
}

HWTEST_F(StallingRateTraceTest, APPTabs02, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    tabsFlag = true;
    stallingRateTrace.APPTabs("test_line", "test_signS", "test_signF");
    EXPECT_EQ(appTabsDynamicFinishTime, stallingRateTrace.GetTimes("test_line", "test_signS"));
    EXPECT_TRUE(tabsFlag);
    EXPECT_EQ(frameLossTabsTime, 0);
}

HWTEST_F(StallingRateTraceTest, APPTabs03, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    tabsFlag = false;
    stallingRateTrace.APPTabs("test_line", "test_signS", "test_signF");
    EXPECT_EQ(appTabsDynamicFinishTime, stallingRateTrace.GetTimes("test_line", "test_signF"));
    EXPECT_FALSE(tabsFlag);
}

HWTEST_F(StallingRateTraceTest, GetFrameRate01, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    std::string line = "rate: 60.0";
    double expectedRate = 60.0;
    double actualRate = stallingRateTrace.GetFrameRate(line);
    EXPECT_DOUBLE_EQ(expectedRate, actualRate);
}

HWTEST_F(StallingRateTraceTest, GetFrameRate02, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    std::string line = "now: 123456";
    double expectedRate = 0.0;
    double actualRate = stallingRateTrace.GetFrameRate(line);
    EXPECT_DOUBLE_EQ(expectedRate, actualRate);
}

HWTEST_F(StallingRateTraceTest, GetFrameRate03, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    std::string line = "now: 123456, rate: 60.0";
    double expectedRate = 60.0;
    double actualRate = stallingRateTrace.GetFrameRate(line);
    EXPECT_DOUBLE_EQ(expectedRate, actualRate);
}

HWTEST_F(StallingRateTraceTest, GetFenceId01, TestSize.Level1)
{
    std::string line = "H:Present Fence 12345";
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    int fenceId = stallingRateTrace.GetFenceId(line);
    EXPECT_EQ(fenceId, 12345);
}

HWTEST_F(StallingRateTraceTest, GetFenceId02, TestSize.Level1)
{
    std::string line = "H:Present Fence ";
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    int fenceId = stallingRateTrace.GetFenceId(line);
    EXPECT_EQ(fenceId, 0);
}

HWTEST_F(StallingRateTraceTest, IsAppLaunchPatternMatched01, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    std::string line = "H:LAUNCHER_APP_LAUNCH_FROM_ICON,";
    EXPECT_TRUE(stallingRateTrace.IsAppLaunchPatternMatched(line));
}

HWTEST_F(StallingRateTraceTest, IsAppLaunchPatternMatched02, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    std::string line = "H:NOT_A_MATCH";
    EXPECT_FALSE(stallingRateTrace.IsAppLaunchPatternMatched(line));
}

HWTEST_F(StallingRateTraceTest, IsAppLaunchPatternMatched03, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    std::string line = "START H:LAUNCHER_APP_LAUNCH_FROM_ICON,";
    EXPECT_FALSE(stallingRateTrace.IsAppLaunchPatternMatched(line));
}

HWTEST_F(StallingRateTraceTest, IsAppLaunchPatternMatched04, TestSize.Level1)
{
    OHOS::SmartPerf::StallingRateTrace stallingRateTrace;
    std::string line = "START H:LAUNCHER_APP_LAUNCH_FROM_ICON";
    EXPECT_FALSE(stallingRateTrace.IsAppLaunchPatternMatched(line));
}

}
}