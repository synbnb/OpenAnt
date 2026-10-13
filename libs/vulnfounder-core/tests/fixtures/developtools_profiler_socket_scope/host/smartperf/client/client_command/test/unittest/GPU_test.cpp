/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <exception>
#include <iostream>
#include <string>
#include <gtest/gtest.h>
#include <unistd.h>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <functional>
#include "GPU.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class SPdaemonGpuTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: GPU::GetInstance
 * @tc.desc: Test GetInstance returns singleton instance
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, GetInstanceTest001, TestSize.Level1)
{
    GPU &instance1 = GPU::GetInstance();
    GPU &instance2 = GPU::GetInstance();
    
    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: GPU::SetRkFlag
 * @tc.desc: Test SetRkFlag sets rkFlag to true
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, SetRkFlagTest001, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    gpu.SetRkFlag();
    auto result = gpu.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: GPU::ItemData
 * @tc.desc: Test ItemData with default rkFlag (false)
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, ItemDataTest001, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    auto result = gpu.ItemData();
    
    EXPECT_FALSE(result.empty());
    EXPECT_GE(result.size(), 2);
}

/**
 * @tc.name: GPU::ItemData
 * @tc.desc: Test ItemData with rkFlag set to true
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, ItemDataTest002, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    gpu.SetRkFlag();
    
    auto result = gpu.ItemData();
    
    EXPECT_FALSE(result.empty());
    EXPECT_GE(result.size(), 2);
}

/**
 * @tc.name: GPU::ItemData
 * @tc.desc: Test ItemData returns expected keys
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, ItemDataTest003, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    auto result = gpu.ItemData();
    
    EXPECT_NE(result.find("gpuFrequency"), result.end());
    EXPECT_NE(result.find("gpuLoad"), result.end());
}

/**
 * @tc.name: GPU::ItemData
 * @tc.desc: Test ItemData with rkFlag true returns expected keys
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, ItemDataTest004, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    gpu.SetRkFlag();
    
    auto result = gpu.ItemData();
    
    EXPECT_NE(result.find("gpuFrequency"), result.end());
    EXPECT_NE(result.find("gpuLoad"), result.end());
}

/**
 * @tc.name: GPU::ItemData
 * @tc.desc: Test ItemData multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, ItemDataTest005, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    auto result1 = gpu.ItemData();
    auto result2 = gpu.ItemData();
    auto result3 = gpu.ItemData();
    
    EXPECT_FALSE(result1.empty());
    EXPECT_FALSE(result2.empty());
    EXPECT_FALSE(result3.empty());
}

/**
 * @tc.name: GPU::ItemData
 * @tc.desc: Test ItemData with rkFlag true multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, ItemDataTest006, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    gpu.SetRkFlag();
    
    auto result1 = gpu.ItemData();
    auto result2 = gpu.ItemData();
    
    EXPECT_FALSE(result1.empty());
    EXPECT_FALSE(result2.empty());
}

/**
 * @tc.name: GPU::ItemData
 * @tc.desc: Test ItemData returns valid frequency value
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, ItemDataTest007, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    auto result = gpu.ItemData();
    
    EXPECT_FALSE(result["gpuFrequency"].empty());
}

/**
 * @tc.name: GPU::ItemData
 * @tc.desc: Test ItemData returns valid load value
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, ItemDataTest008, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    auto result = gpu.ItemData();
    
    EXPECT_FALSE(result["gpuLoad"].empty());
}

/**
 * @tc.name: GPU::GetGpuFreq
 * @tc.desc: Test GetGpuFreq returns valid frequency
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, GetGpuFreqTest001, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    int freq = gpu.GetGpuFreq();
    
    EXPECT_GE(freq, 0);
}

/**
 * @tc.name: GPU::GetGpuFreq
 * @tc.desc: Test GetGpuFreq multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, GetGpuFreqTest002, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    int freq1 = gpu.GetGpuFreq();
    int freq2 = gpu.GetGpuFreq();
    
    EXPECT_GE(freq1, 0);
    EXPECT_GE(freq2, 0);
}

/**
 * @tc.name: GPU::GetGpuLoad
 * @tc.desc: Test GetGpuLoad returns valid load
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, GetGpuLoadTest001, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    float load = gpu.GetGpuLoad();
    
    EXPECT_GE(load, 0.0f);
}

/**
 * @tc.name: GPU::GetGpuLoad
 * @tc.desc: Test GetGpuLoad multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, GetGpuLoadTest002, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    float load1 = gpu.GetGpuLoad();
    float load2 = gpu.GetGpuLoad();
    
    EXPECT_GE(load1, 0.0f);
    EXPECT_GE(load2, 0.0f);
}

/**
 * @tc.name: GPU::GetRkGpuFreq
 * @tc.desc: Test GetRkGpuFreq returns valid frequency
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, GetRkGpuFreqTest001, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    int32_t freq = gpu.GetRkGpuFreq();
    
    EXPECT_GE(freq, 0);
}

/**
 * @tc.name: GPU::GetRkGpuFreq
 * @tc.desc: Test GetRkGpuFreq multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, GetRkGpuFreqTest002, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    int32_t freq1 = gpu.GetRkGpuFreq();
    int32_t freq2 = gpu.GetRkGpuFreq();
    
    EXPECT_GE(freq1, 0);
    EXPECT_GE(freq2, 0);
}

/**
 * @tc.name: GPU::GetRkGpuLoad
 * @tc.desc: Test GetRkGpuLoad returns valid load
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, GetRkGpuLoadTest001, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    float load = gpu.GetRkGpuLoad();
    
    EXPECT_GE(load, 0.0f);
}

/**
 * @tc.name: GPU::GetRkGpuLoad
 * @tc.desc: Test GetRkGpuLoad multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, GetRkGpuLoadTest002, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    float load1 = gpu.GetRkGpuLoad();
    float load2 = gpu.GetRkGpuLoad();
    
    EXPECT_GE(load1, 0.0f);
    EXPECT_GE(load2, 0.0f);
}

/**
 * @tc.name: GPU::SetRkFlag
 * @tc.desc: Test SetRkFlag followed by ItemData
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, SetRkFlagTest002, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    auto result1 = gpu.ItemData();
    gpu.SetRkFlag();
    auto result2 = gpu.ItemData();
    
    EXPECT_FALSE(result1.empty());
    EXPECT_FALSE(result2.empty());
}

/**
 * @tc: GPU::ItemData
 * @tc.desc: Test ItemData with rkFlag false uses standard methods
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, ItemDataTest009, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    auto result = gpu.ItemData();
    
    EXPECT_FALSE(result.empty());
    EXPECT_GE(result.size(), 2);
}

/**
 * @tc.name: GPU::ItemData
 * @tc.desc: Test ItemData with rkFlag true uses RK methods
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, ItemDataTest010, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    gpu.SetRkFlag();
    
    auto result = gpu.ItemData();
    
    EXPECT_FALSE(result.empty());
    EXPECT_GE(result.size(), 2);
}

/**
 * @tc.name: GPU::GetGpuLoad
 * @tc.desc: Test GetGpuLoad returns float value
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, GetGpuLoadTest003, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    float load = gpu.GetGpuLoad();
    
    EXPECT_GE(load, 0.0f);
    EXPECT_LE(load, 100.0f);
}

/**
 * @tc.name: GPU::GetRkGpuLoad
 * @tc.desc: Test GetRkGpuLoad returns float value
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, GetRkGpuLoadTest003, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    float load = gpu.GetRkGpuLoad();
    
    EXPECT_GE(load, 0.0f);
}

/**
 * @tc.name: GPU::GetGpuFreq
 * @tc.desc: Test GetGpuFreq returns int value
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, GetGpuFreqTest003, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    int freq = gpu.GetGpuFreq();
    
    EXPECT_GE(freq, 0);
}

/**
 * @tc.name: GPU::GetRkGpuFreq
 * @tc.desc: Test GetRkGpuFreq returns int32_t value
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, GetRkGpuFreqTest003, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    int32_t freq = gpu.GetRkGpuFreq();
    
    EXPECT_GE(freq, 0);
}

/**
 * @tc.name: GPU::ItemData
 * @tc.desc: Test ItemData returns consistent map size
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGpuTest, ItemDataTest011, TestSize.Level1)
{
    GPU &gpu = GPU::GetInstance();
    
    auto result1 = gpu.ItemData();
    auto result2 = gpu.ItemData();
    
    EXPECT_EQ(result1.size(), result2.size());
}
}
}
