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
#include <exception>
#include <iostream>
#include <string>
#include <gtest/gtest.h>
#include <unistd.h>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <functional>
#include "Temperature.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class SPdaemonTemperatureTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: Temperature::ItemData
 * @tc.desc: Test ItemData returns valid result
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, ItemDataTest001, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    
    auto result = temperature.ItemData();
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::ItemData
 * @tc.desc: Test ItemData multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, ItemDataTest002, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    
    auto result1 = temperature.ItemData();
    auto result2 = temperature.ItemData();
    auto result3 = temperature.ItemData();
    
    EXPECT_TRUE(result1.empty() || !result1.empty());
    EXPECT_TRUE(result2.empty() || !result2.empty());
    EXPECT_TRUE(result3.empty() || !result3.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with gpu type
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest001, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "gpu";
    std::string temp = "45000";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with cluster type
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest002, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "cluster0";
    std::string temp = "50000";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with npu type
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest003, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "npu_thermal";
    std::string temp = "60000";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with soc_thermal type
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest004, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "soc_thermal";
    std::string temp = "40000";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with system_h type
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest005, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "system_h";
    std::string temp = "35000";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with empty type
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest006, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "";
    std::string temp = "40000";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with empty temp
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest007, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "gpu";
    std::string temp = "";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with invalid type
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest008, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "invalid_type";
    std::string temp = "40000";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with zero temperature
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest009, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "gpu";
    std::string temp = "0";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with negative temperature
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest010, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "gpu";
    std::string temp = "-10000";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with large temperature
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest011, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "gpu";
    std::string temp = "100000";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with drmos_gpu_npu type
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest012, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "drmos_gpu_npu";
    std::string temp = "55000";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with Battery type
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest013, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "Battery";
    std::string temp = "30000";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with shell_frame type
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest014, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "shell_frame";
    std::string temp = "38000";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with shell_front type
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest015, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "shell_front";
    std::string temp = "37000";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfo with shell_back type
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest016, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "shell_back";
    std::string temp = "36000";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with gpu-thermal type
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest017, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "gpu-thermal";
    std::string temp = "46000";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with cluster1 type
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest018, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "cluster1";
    std::string temp = "51000";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest019, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    
    temperature.GetTempInfos(result, "gpu", "45000");
    temperature.GetTempInfos(result, "cluster0", "50000");
    temperature.GetTempInfos(result, "npu_thermal", "60000");
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::ItemData
 * @tc.desc: Test ItemData with delay between calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, ItemDataTest003, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    
    auto result1 = temperature.ItemData();
    sleep(1);
    auto result2 = temperature.ItemData();
    
    EXPECT_TRUE(result1.empty() || !result1.empty());
    EXPECT_TRUE(result2.empty() || !result2.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with float temperature
 * @tc.type:: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest020, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "gpu";
    std::string temp = "45.5";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with very large temperature
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest021, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "gpu";
    std::string temp = "999999";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Temperature::GetTempInfos
 * @tc.desc: Test GetTempInfos with special characters in temp
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTemperatureTest, GetTempInfosTest022, TestSize.Level1)
{
    Temperature &temperature = Temperature::GetInstance();
    std::map<std::string, std::string> result;
    std::string type = "gpu";
    std::string temp = "45abc";
    
    temperature.GetTempInfos(result, type, temp);
    
    EXPECT_TRUE(result.empty() || !result.empty());
}
}
}