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

#include <string>
#include <thread>
#include <vector>
#include <gtest/gtest.h>
#include "sp_utils.h"
#include "RAM.h"
#include "GPU.h"
#include "CPU.h"
#include "FPS.h"
#include "Temperature.h"
#include "Power.h"
#include "Capture.h"
#include "Network.h"
#include "parse_click_complete_trace.h"
#include "parse_click_response_trace.h"
#include "parse_slide_fps_trace.h"
#include "DDR.h"
#include "navigation.h"
#include <ctime>
#include <sys/time.h>
using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class SPdaemonTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: CpuTestCase
 * @tc.desc: Test CPU
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTest, CpuTestCase, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::string packName = "ohos.samples.ecg";

    std::map<std::string, std::string> cpuItemData = cpu.ItemData();
    cpu.SetPackageName(packName);
    std::vector<CpuFreqs> cpuFreqs = cpu.GetCpuFreq();
    std::vector<CpuUsageInfos> getCpuUsage = cpu.GetCpuUsage();
    std::map<std::string, std::string> getSysProcessCpuLoad = cpu.GetSysProcessCpuLoad();

    std::string cmd = "SP_daemon -N 1 -PKG ohos.samples.ecg -c";
    std::string result = "";
    bool flag = false;
    auto ret = SPUtils::LoadCmd(cmd, result);
    std::string::size_type strOne = result.find("command exec finished!");
    if ((strOne != result.npos)) {
        flag = true;
    }
    EXPECT_EQ(ret, true);
    EXPECT_TRUE(flag);
}

/**
 * @tc.name: GpuTestCase
 * @tc.desc: Test GPU
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTest, GpuTestCase, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    int getGpuFreq = 0;
    float getGpuLoad = 0.0;
    std::map<std::string, std::string> gpuItemData = gpu.ItemData();
    getGpuFreq = gpu.GetGpuFreq();
    getGpuLoad = gpu.GetGpuLoad();

    std::string cmd = "SP_daemon -N 1 -g";
    std::string result = "";
    bool flag = false;
    auto ret = SPUtils::LoadCmd(cmd, result);
    std::string::size_type strOne = result.find("command exec finished!");
    if ((strOne != result.npos)) {
        flag = true;
    }
    EXPECT_EQ(ret, true);
    EXPECT_TRUE(flag);
}

/**
 * @tc.name: FpsTestCase
 * @tc.desc: Test FPS
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTest, FpsTestCase, TestSize.Level1)
{
    FPS &fps = FPS::GetInstance();
    std::string packName = "ohos.samples.ecg";
    std::string surfaceViewName;
    FpsInfo fpsInfoResult;

    long long mod = 1e9;
    struct timespec time1 = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &time1);
    long long currTimeDump = (time1.tv_sec - 1) * mod + time1.tv_nsec;
    std::string currTimeDumpStr = std::to_string(currTimeDump);

    fps.SetFpsCurrentFpsTime(fpsInfoResult);
    fps.SetPackageName(packName);
    fps.SetLayerName(surfaceViewName);
    fps.CalcFpsAndJitters(true, currTimeDumpStr, true);

    std::string cmd = "SP_daemon -N 1 -PKG ohos.samples.ecg -f";
    std::string result = "";
    bool flag = false;
    auto ret = SPUtils::LoadCmd(cmd, result);
    std::string::size_type strOne = result.find("command exec finished!");
    if ((strOne != result.npos)) {
        flag = true;
    }
    EXPECT_EQ(ret, true);
    EXPECT_TRUE(flag);
}

/**
 * @tc.name: TemperatureTestCase
 * @tc.desc: Test Temperature
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTest, TemperatureTestCase, TestSize.Level1)
{
    std::string cmd = "SP_daemon -N 1 -t";
    std::string result = "";
    bool flag = false;
    auto ret = SPUtils::LoadCmd(cmd, result);
    std::string::size_type strOne = result.find("command exec finished!");
    if ((strOne != result.npos)) {
        flag = true;
    }
    EXPECT_EQ(ret, true);
    EXPECT_TRUE(flag);
}

/**
 * @tc.name: PowerTestCase
 * @tc.desc: Test Power
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTest, PowerTestCase, TestSize.Level1)
{
    std::string cmd = "SP_daemon -N 1 -p";
    std::string result = "";
    bool flag = false;
    auto ret = SPUtils::LoadCmd(cmd, result);
    std::string::size_type strOne = result.find("command exec finished!");
    if ((strOne != result.npos)) {
        flag = true;
    }
    EXPECT_EQ(ret, true);
    EXPECT_TRUE(flag);
}

/**
 * @tc.name: RamTestCase
 * @tc.desc: Test RAM
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTest, RamTestCase, TestSize.Level1)
{
    RAM &ram = RAM::GetInstance();
    std::string packName = "ohos.samples.ecg";

    ram.SetFirstFlag();
    ram.SetPackageName(packName);
    ram.ThreadGetPss();
    ram.TriggerGetPss();

    std::string cmd = "SP_daemon -N 1 -PKG ohos.samples.ecg -r";
    std::string result = "";
    bool flag = false;
    auto ret = SPUtils::LoadCmd(cmd, result);
    std::string::size_type strOne = result.find("command exec finished!");
    if ((strOne != result.npos)) {
        flag = true;
    }
    EXPECT_EQ(ret, true);
    EXPECT_TRUE(flag);
}

/**
 * @tc.name: NetWorkTestCase
 * @tc.desc: Test NetWork
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTest, NetWorkTestCase, TestSize.Level1)
{
    std::string cmd = "SP_daemon -N 1 -net";
    std::string result = "";
    bool flag = false;
    auto ret = SPUtils::LoadCmd(cmd, result);
    std::string::size_type strOne = result.find("command exec finished!");
    if ((strOne != result.npos)) {
        flag = true;
    }
    EXPECT_EQ(ret, true);
    EXPECT_TRUE(flag);
}

/**
 * @tc.name: StartTestCase
 * @tc.desc: Test Start
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTest, StartTestCase, TestSize.Level1)
{
    std::string cmd = "SP_daemon -start -g";
    std::string result = "";
    bool flag = false;
    auto ret = SPUtils::LoadCmd(cmd, result);
    std::string::size_type strOne = result.find("Collection");
    std::string::size_type strTwo = result.find("begins");
    if ((strOne != result.npos) && (strTwo != result.npos)) {
        flag = true;
    }
    EXPECT_EQ(ret, true);
    EXPECT_TRUE(flag);
}

/**
 * @tc.name: StopTestCase
 * @tc.desc: Test Stop
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTest, StopTestCase, TestSize.Level1)
{
    std::string cmd = "SP_daemon -stop";
    std::string result = "";
    bool flag = false;
    auto ret = SPUtils::LoadCmd(cmd, result);
    std::string::size_type strOne = result.find("Collection");
    std::string::size_type strTwo = result.find("ended");
    if ((strOne != result.npos) && (strTwo != result.npos)) {
        flag = true;
    }
    EXPECT_EQ(ret, true);
    EXPECT_TRUE(flag);
}

/**
 * @tc.name: FrameLossTestCase
 * @tc.desc: Test FrameLoss
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTest, FrameLossTestCase, TestSize.Level1)
{
    std::string cmd = "SP_daemon -editor frameLoss";
    std::string result = "";
    bool flag = false;
    auto ret = SPUtils::LoadCmd(cmd, result);
    std::string::size_type strOne = result.find("BUNDLE_NAME");
    std::string::size_type strTwo = result.find("TOTAL_APP_MISSED_FRAMES");
    if ((strOne != result.npos) && (strTwo != result.npos)) {
        flag = true;
    }
    EXPECT_EQ(ret, true);
    EXPECT_TRUE(flag);
}

/**
 * @tc.name: DdrTestCase
 * @tc.desc: Test DDR
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTest, DdrTestCase, TestSize.Level1)
{
    std::string cmd = "SP_daemon -N 1 -d";
    std::string result = "";
    bool flag = false;
    auto ret = SPUtils::LoadCmd(cmd, result);
    DDR &ddr = DDR::GetInstance();
    ddr.SetRkFlag();
    ddr.GetDdrFreq();
    std::string::size_type strOne = result.find("command exec finished!");
    if ((strOne != result.npos)) {
        flag = true;
    }
    EXPECT_EQ(ret, true);
    EXPECT_TRUE(flag);
}

/**
 * @tc.name: Navigation
 * @tc.desc: Test Navigation
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTest, Navigation, TestSize.Level1)
{
    Navigation &nav = Navigation::GetInstance();
    std::string packName = "ohos.samples.ecg";

    std::map<std::string, std::string> navItemData = nav.ItemData();

    std::string cmd = "SP_daemon -N 1 -PKG ohos.samples.ecg -nav";
    std::string result = "";
    bool flag = false;
    auto ret = SPUtils::LoadCmd(cmd, result);
    std::string::size_type strOne = result.find("command exec finished!");
    if ((strOne != result.npos)) {
        flag = true;
    }
    EXPECT_EQ(ret, true);
    EXPECT_TRUE(flag);
}
} // namespace OHOS
} // namespace SmartPerf