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
#include <iostream>
#include <sstream>
#include <thread>
#include <chrono>
#include "unistd.h"
#include "sp_utils.h"
#include "ByTrace.h"
#include "common.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class ByTraceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(ByTraceTest, SetByTraceTest01, TestSize.Level1)
{
    ByTrace &byTrace = ByTrace::GetInstance();
    byTrace.jittersAndLowFps = "";
    byTrace.SetByTrace();
    long long jitterTimes = byTrace.GetThreshold();
    int lowFps = byTrace.GetLowFps();
    EXPECT_EQ(jitterTimes, 0);
    EXPECT_EQ(lowFps, -1);
}

HWTEST_F(ByTraceTest, SetByTraceTest02, TestSize.Level1)
{
    ByTrace &byTrace = ByTrace::GetInstance();
    byTrace.jittersAndLowFps = "fpsJitterTime=100||lowFps=20";
    byTrace.SetByTrace();
    long long jitterTimes = byTrace.GetThreshold();
    int lowFps = byTrace.GetLowFps();
    EXPECT_EQ(jitterTimes, 100);
    EXPECT_EQ(lowFps, 20);
}

HWTEST_F(ByTraceTest, SetByTraceTest03, TestSize.Level1)
{
    ByTrace &byTrace = ByTrace::GetInstance();
    byTrace.jittersAndLowFps = "fpsJitterTime=100";
    byTrace.SetByTrace();
    EXPECT_EQ(byTrace.GetThreshold(), 100);
    EXPECT_EQ(byTrace.GetLowFps(), 20);
}

HWTEST_F(ByTraceTest, ClearTraceFilesTest, TestSize.Level1)
{
    ByTrace &byTrace = ByTrace::GetInstance();
    byTrace.traceCpPath_ = "/data/local/tmp/hitrace";
    byTrace.ClearTraceFiles();
    EXPECT_FALSE(std::filesystem::exists(byTrace.traceCpPath_));
}

HWTEST_F(ByTraceTest, RemoveTraceFiles01, TestSize.Level1)
{
    ByTrace &byTrace = ByTrace::GetInstance();
    byTrace.traceCpPath_ = "/data/local/tmp/hitrace";
    std::filesystem::create_directory(byTrace.traceCpPath_);
    std::ofstream file(byTrace.traceCpPath_ + "/test_file.txt");
    file << "test content";
    file.close();
    byTrace.RemoveTraceFiles();
    EXPECT_FALSE(std::filesystem::exists(byTrace.traceCpPath_ + "/test_file.txt"));
}

HWTEST_F(ByTraceTest, RemoveTraceFiles02, TestSize.Level1)
{
    ByTrace &byTrace = ByTrace::GetInstance();
    byTrace.traceCpPath_ = "/data/local/tmp/hitrace";
    std::filesystem::remove_all(byTrace.traceCpPath_);
    byTrace.RemoveTraceFiles();
    EXPECT_FALSE(std::filesystem::exists(byTrace.traceCpPath_));
}

HWTEST_F(ByTraceTest, CheckFpsJittersTest01, TestSize.Level1)
{
    ByTrace &byTrace = ByTrace::GetInstance();
    long long jitters = 0;
    int cfps = 60;
    byTrace.times = 3;
    byTrace.lastEnableTime = 1000;
    byTrace.nowTime = 2000;
    byTrace.CheckFpsJitters(jitters, cfps);
    EXPECT_EQ(byTrace.lastEnableTime, 0);
}

HWTEST_F(ByTraceTest, CheckFpsJittersTest02, TestSize.Level1)
{
    ByTrace &byTrace = ByTrace::GetInstance();
    long long jitters = 0;
    int cfps = 60;
    byTrace.times = 1;
    byTrace.lastEnableTime = 1000;
    byTrace.nowTime = 1001;
    byTrace.CheckFpsJitters(jitters, cfps);
    EXPECT_EQ(byTrace.lastEnableTime, 1000);
}
}
}