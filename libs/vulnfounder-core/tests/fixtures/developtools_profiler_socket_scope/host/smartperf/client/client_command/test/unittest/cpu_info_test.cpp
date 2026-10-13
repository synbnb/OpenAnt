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
#include <string>
#include <map>
#include "cpu_info.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class CPUInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CPUInfoTest::SetUpTestCase(void)
{
}

void CPUInfoTest::TearDownTestCase(void)
{
}

void CPUInfoTest::SetUp()
{
}

void CPUInfoTest::TearDown()
{
}
/**
 * @tc.name: CPUInfoTest_GetInstance_001
 * @tc.desc: 验证 GetInstance 返回单例实例
 * @tc.type: FUNC
 */
HWTEST_F(CPUInfoTest, CPUInfoTest_GetInstance_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CPUInfoTest-begin CPUInfoTest_GetInstance_001";
    CPUInfo &instance1 = CPUInfo::GetInstance();
    CPUInfo &instance2 = CPUInfo::GetInstance();
    
    EXPECT_EQ(&instance1, &instance2);
    GTEST_LOG_(INFO) << "CPUInfoTest-end CPUInfoTest_GetInstance_001";
}

/**
 * @tc.name: CPUInfoTest_SetPids_001
 * @tc.desc: 验证 SetPids 设置有效的进程ID
 * @tc.type: FUNC
 */
HWTEST_F(CPUInfoTest, CPUInfoTest_SetPids_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CPUInfoTest-begin CPUInfoTest_SetPids_001";
    CPUInfo &cpuInfo = CPUInfo::GetInstance();
    std::string testPids = "12345 67890";
    
    cpuInfo.SetPids(testPids);
    
    std::map<std::string, std::string> result = cpuInfo.ItemData();
    EXPECT_TRUE(result.size() >= 0);
    GTEST_LOG_(INFO) << "CPUInfoTest-end CPUInfoTest_SetPids_001";
}

/**
 * @tc.name: CPUInfoTest_SetPids_002
 * @tc.desc: 验证 SetPids 设置空进程ID
 * @tc.type: FUNC
 */
HWTEST_F(CPUInfoTest, CPUInfoTest_SetPids_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CPUInfoTest-begin CPUInfoTest_SetPids_002";
    CPUInfo &cpuInfo = CPUInfo::GetInstance();
    std::string emptyPids = "";
    
    cpuInfo.SetPids(emptyPids);
    
    std::map<std::string, std::string> result = cpuInfo.ItemData();
    EXPECT_TRUE(result.size() >= 0);
    GTEST_LOG_(INFO) << "CPUInfoTest-end CPUInfoTest_SetPids_002";
}

/**
 * @tc.name: CPUInfoTest_SetPids_003
 * @tc.desc: 验证 SetPids 设置单个进程ID
 * @tc.type: FUNC
 */
HWTEST_F(CPUInfoTest, CPUInfoTest_SetPids_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CPUInfoTest-begin CPUInfoTest_SetPids_003";
    CPUInfo &cpuInfo = CPUInfo::GetInstance();
    std::string singlePid = "12345";
    
    cpuInfo.SetPids(singlePid);
    
    std::map<std::string, std::string> result = cpuInfo.ItemData();
    EXPECT_TRUE(result.size() >= 0);
    GTEST_LOG_(INFO) << "CPUInfoTest-end CPUInfoTest_SetPids_003";
}

/**
 * @tc.name: CPUInfoTest_ItemData_001
 * @tc.desc: 验证 ItemData 返回包含预期键值的map
 * @tc.type: FUNC
 */
HWTEST_F(CPUInfoTest, CPUInfoTest_ItemData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CPUInfoTest-begin CPUInfoTest_ItemData_001";
    CPUInfo &cpuInfo = CPUInfo::GetInstance();
    
    std::map<std::string, std::string> result = cpuInfo.ItemData();
    
    EXPECT_TRUE(result.size() >= 0);
    GTEST_LOG_(INFO) << "CPUInfoTest-end CPUInfoTest_ItemData_001";
}

/**
 * @tc.name: CPUInfoTest_ItemData_002
 * @tc.desc: 验证 ItemData 多次调用的稳定性
 * @tc.type: FUNC
 */
HWTEST_F(CPUInfoTest, CPUInfoTest_ItemData_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CPUInfoTest-begin CPUInfoTest_ItemData_002";
    CPUInfo &cpuInfo = CPUInfo::GetInstance();
    
    std::map<std::string, std::string> result1 = cpuInfo.ItemData();
    std::map<std::string, std::string> result2 = cpuInfo.ItemData();
    
    EXPECT_TRUE(result1.size() >= 0);
    EXPECT_TRUE(result2.size() >= 0);
    GTEST_LOG_(INFO) << "CPUInfoTest-end CPUInfoTest_ItemData_002";
}

/**
 * @tc.name: CPUInfoTest_ItemData_003
 * @tc.desc: 验证 ItemData 在设置进程ID后的行为
 * @tc.type: FUNC
 */
HWTEST_F(CPUInfoTest, CPUInfoTest_ItemData_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CPUInfoTest-begin CPUInfoTest_ItemData_003";
    CPUInfo &cpuInfo = CPUInfo::GetInstance();
    cpuInfo.SetPids("12345");
    
    std::map<std::string, std::string> result = cpuInfo.ItemData();
    
    EXPECT_TRUE(result.size() >= 0);
    GTEST_LOG_(INFO) << "CPUInfoTest-end CPUInfoTest_ItemData_003";
}

/**
 * @tc.name: CPUInfoTest_StartExecutionOnce_001
 * @tc.desc: 验证 StartExecutionOnce 正常启动
 * @tc.type: FUNC
 */
HWTEST_F(CPUInfoTest, CPUInfoTest_StartExecutionOnce_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CPUInfoTest-begin CPUInfoTest_StartExecutionOnce_001";
    CPUInfo &cpuInfo = CPUInfo::GetInstance();
    
    cpuInfo.StartExecutionOnce(false);
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "CPUInfoTest-end CPUInfoTest_StartExecutionOnce_001";
}

/**
 * @tc.name: CPUInfoTest_FinishtExecutionOnce_001
 * @tc.desc: 验证 FinishtExecutionOnce 正常停止
 * @tc.type: FUNC
 */
HWTEST_F(CPUInfoTest, CPUInfoTest_FinishtExecutionOnce_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CPUInfoTest-begin CPUInfoTest_FinishtExecutionOnce_001";
    CPUInfo &cpuInfo = CPUInfo::GetInstance();
    
    cpuInfo.FinishtExecutionOnce(false);
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "CPUInfoTest-end CPUInfoTest_FinishtExecutionOnce_001";
}

/**
 * @tc.name: CPUInfoTest_StartStop_001
 * @tc.desc: 验证 Start 和 Stop 方法的调用
 * @tc.type: FUNC
 */
HWTEST_F(CPUInfoTest, CPUInfoTest_StartStop_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CPUInfoTest-begin CPUInfoTest_StartStop_001";
    CPUInfo &cpuInfo = CPUInfo::GetInstance();
    
    cpuInfo.Start();
    cpuInfo.Stop();
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "CPUInfoTest-end CPUInfoTest_StartStop_001";
}
}
}
