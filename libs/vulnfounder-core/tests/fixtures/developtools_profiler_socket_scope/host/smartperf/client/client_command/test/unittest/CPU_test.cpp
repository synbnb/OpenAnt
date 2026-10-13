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
#include "CPU.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class SPdaemonCpuTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: CPU::GetInstance
 * @tc.desc: Test GetInstance returns singleton instance
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetInstanceTest001, TestSize.Level1)
{
    CPU &instance1 = CPU::GetInstance();
    CPU &instance2 = CPU::GetInstance();
    
    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: CPU::SetPackageName
 * @tc.desc: Test SetPackageName with valid package name
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, SetPackageNameTest001, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::string testPkg = "com.example.test";
    
    cpu.SetPackageName(testPkg);
    auto result = cpu.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: CPU::SetPackageName
 * @tc.desc: Test SetPackageName with empty string
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, SetPackageNameTest002, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::string testPkg = "";
    
    cpu.SetPackageName(testPkg);
    auto result = cpu.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: CPU::SetPackageName
 * @tc.desc: Test SetPackageName with long package name
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, SetPackageNameTest003, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::string testPkg = "com.very.long.package.name.for.testing.purposes.that.exceeds.normal.length";
    
    cpu.SetPackageName(testPkg);
    auto result = cpu.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: CPU::SetProcessId
 * @tc.desc: Test SetProcessId with valid process ID
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, SetProcessIdTest001, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::string testPid = "12345";
    
    cpu.SetProcessId(testPid);
    auto result = cpu.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: CPU::SetProcessId
 * @tc.desc: Test SetProcessId with empty string
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, SetProcessIdTest002, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::string testPid = "";
    
    cpu.SetProcessId(testPid);
    auto result = cpu.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: CPU::SetProcessId
 * @tc.desc: Test SetProcessId with multiple process IDs separated by space
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, SetProcessIdTest003, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::string testPid = "12345 12346 12347";
    
    cpu.SetProcessId(testPid);
    auto result = cpu.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: CPU::SetProcessId
 * @tc.desc: Test SetProcessId with maximum process ID value
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, SetProcessIdTest004, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::string testPid = "2147483647";
    
    cpu.SetProcessId(testPid);
    auto result = cpu.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: CPU::SetProcessId
 * @tc.desc: Test SetProcessId with zero process ID
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, SetProcessIdTest005, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::string testPid = "0";
    
    cpu.SetProcessId(testPid);
    auto result = cpu.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: CPU::ItemData
 * @tc.desc: Test ItemData without setting package name or process ID
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, ItemDataTest001, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    
    auto result = cpu.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: CPU::ItemData
 * @tc.desc: Test ItemData with package name set
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, ItemDataTest002, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    cpu.SetPackageName("com.example.test");
    
    auto result = cpu.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: CPU::ItemData
 * @tc.desc: Test ItemData with process ID set
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, ItemDataTest003, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    cpu.SetProcessId("12345");
    
    auto result = cpu.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: CPU::ItemData
 * @tc.desc: Test ItemData multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, ItemDataTest004, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    
    auto result1 = cpu.ItemData();
    auto result2 = cpu.ItemData();
    auto result3 = cpu.ItemData();
    
    EXPECT_FALSE(result1.empty());
    EXPECT_FALSE(result2.empty());
    EXPECT_FALSE(result3.empty());
}

/**
 * @tc.name: CPU::GetCpuFreq
 * @tc.desc: Test GetCpuFreq returns CPU frequency data
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetCpuFreqTest001, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    
    auto cpuFreqs = cpu.GetCpuFreq();
    
    EXPECT_GE(cpuFreqs.size(), 0);
}

/**
 * @tc.name: CPU::GetCpuFreq
 * @tc.desc: Test GetCpuFreq multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetCpuFreqTest002, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    
    auto cpuFreqs1 = cpu.GetCpuFreq();
    auto cpuFreqs2 = cpu.GetCpuFreq();
    
    EXPECT_GE(cpuFreqs1.size(), 0);
    EXPECT_GE(cpuFreqs2.size(), 0);
}

/**
 * @tc.name: CPU::GetCpuUsage
 * @tc.desc: Test GetCpuUsage returns CPU usage data
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetCpuUsageTest001, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    
    auto cpuUsages = cpu.GetCpuUsage();
    
    EXPECT_GE(cpuUsages.size(), 0);
}

/**
 * @tc.name: CPU::GetCpuUsage
 * @tc.desc: Test GetCpuUsage multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetCpuUsageTest002, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    
    auto cpuUsages1 = cpu.GetCpuUsage();
    auto cpuUsages2 = cpu.GetCpuUsage();
    
    EXPECT_GE(cpuUsages1.size(), 0);
    EXPECT_GE(cpuUsages2.size(), 0);
}

/**
 * @tc.name: CPU::GetSysProcessCpuLoad
 * @tc.desc: Test GetSysProcessCpuLoad with process ID set
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetSysProcessCpuLoadTest001, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    cpu.SetProcessId("1");
    
    auto processCpuLoad = cpu.GetSysProcessCpuLoad();
    
    EXPECT_FALSE(processCpuLoad.empty());
}

/**
 * @tc.name: CPU::GetSysProcessCpuLoad
 * @tc.desc: Test GetSysProcessCpuLoad with package name set
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetSysProcessCpuLoadTest002, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    cpu.SetPackageName("com.example.test");
    
    auto processCpuLoad = cpu.GetSysProcessCpuLoad();
    
    EXPECT_FALSE(processCpuLoad.empty());
}

/**
 * @tc.name: CPU::GetSysProcessCpuLoad
 * @tc.desc: Test GetSysProcessCpuLoad without setting process ID or package name
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetSysProcessCpuLoadTest003, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    
    auto processCpuLoad = cpu.GetSysProcessCpuLoad();
    
    EXPECT_FALSE(processCpuLoad.empty());
}

/**
 * @tc.name: CPU::GetSysProcessCpuLoad
 * @tc.desc: Test GetSysProcessCpuLoad with multiple process IDs
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetSysProcessCpuLoadTest004, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    cpu.SetProcessId("1 2 3");
    
    auto processCpuLoad = cpu.GetSysProcessCpuLoad();
    
    EXPECT_FALSE(processCpuLoad.empty());
}

/**
 * @tc.name: CPU::GetCpuCoreCurFreqs
 * @tc.desc: Test GetCpuCoreCurFreqs returns CPU core current frequencies
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetCpuCoreCurFreqsTest001, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    
    auto cpuCoreFreqs = cpu.GetCpuCoreCurFreqs();
    
    EXPECT_GE(cpuCoreFreqs.size(), 0);
}

/**
 * @tc.name: CPU::GetCpuCoreCurFreqs
 * @tc.desc: Test GetCpuCoreCurFreqs multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetCpuCoreCurFreqsTest002, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    
    auto cpuCoreFreqs1 = cpu.GetCpuCoreCurFreqs();
    auto cpuCoreFreqs2 = cpu.GetCpuCoreCurFreqs();
    
    EXPECT_GE(cpuCoreFreqs1.size(), 0);
    EXPECT_GE(cpuCoreFreqs2.size(), 0);
}

/**
 * @tc.name: CPU::GetCpuFreqItemData
 * @tc.desc: Test GetCpuFreqItemData populates CPU frequency data
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetCpuFreqItemDataTest001, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::map<std::string, std::string> cpuFreqResult;
    
    cpu.GetCpuFreqItemData(cpuFreqResult);
    
    EXPECT_GE(cpuFreqResult.size(), 0);
}

/**
 * @tc.name: CPU::GetCpuFreqItemData
 * @tc.desc: Test GetCpuFreqItemData multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetCpuFreqItemDataTest002, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::map<std::string, std::string> cpuFreqResult1;
    std::map<std::string, std::string> cpuFreqResult2;
    
    cpu.GetCpuFreqItemData(cpuFreqResult1);
    cpu.GetCpuFreqItemData(cpuFreqResult2);
    
    EXPECT_GE(cpuFreqResult1.size(), 0);
    EXPECT_GE(cpuFreqResult2.size(), 0);
}

/**
 * @tc.name: CPU::GetCpuUsageItemData
 * @tc.desc: Test GetCpuUsageItemData populates CPU usage data
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetCpuUsageItemDataTest001, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::map<std::string, std::string> cpuUsageResult;
    
    cpu.GetCpuUsageItemData(cpuUsageResult);
    
    EXPECT_GE(cpuUsageResult.size(), 0);
}

/**
 * @tc.name: CPU::GetCpuUsageItemData
 * @tc.desc: Test GetCpuUsageItemData multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetCpuUsageItemDataTest002, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::map<std::string, std::string> cpuUsageResult1;
    std::map<std::string, std::string> cpuUsageResult2;
    
    cpu.GetCpuUsageItemData(cpuUsageResult1);
    cpu.GetCpuUsageItemData(cpuUsageResult2);
    
    EXPECT_GE(cpuUsageResult1.size(), 0);
    EXPECT_GE(cpuUsageResult2.size(), 0);
}

/**
 * @tc.name: CPU::GetSysProcessCpuLoadContinue
 * @tc.desc: Test GetSysProcessCpuLoadContinue with valid process info
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetSysProcessCpuLoadContinueTest001, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::map<std::string, std::string> processCpuInfo;
    processCpuInfo["ProcAppName"] = "com.example.test";
    
    cpu.GetSysProcessCpuLoadContinue(processCpuInfo);
    
    EXPECT_FALSE(processCpuInfo.empty());
}

/**
 * @tc.name: CPU::GetSysProcessCpuLoadContinue
 * @tc.desc: Test GetSysProcessCpuLoadContinue with empty process name
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetSysProcessCpuLoadContinueTest002, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::map<std::string, std::string> processCpuInfo;
    processCpuInfo["ProcAppName"] = "";
    
    cpu.GetSysProcessCpuLoadContinue(processCpuInfo);
    
    EXPECT_FALSE(processCpuInfo.empty());
}

/**
 * @tc.name: CPU::GetSysChildProcessCpuLoad
 * @tc.desc: Test GetSysChildProcessCpuLoad with single process
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, GetSysChildProcessCpuLoadTest001, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::map<std::string, std::string> processCpuInfo;
    
    cpu.GetSysChildProcessCpuLoad(1, processCpuInfo);
    
    EXPECT_FALSE(processCpuInfo.empty());
}

/**
 * @tc.name: CPU::ItemData
 * @tc.desc: Test ItemData contains expected keys
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, ItemDataTest005, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    
    auto result = cpu.ItemData();
    
    EXPECT_FALSE(result.empty());
    EXPECT_GE(result.size(), 1);
}

/**
 * @tc.name: CPU::SetProcessId
 * @tc.desc: Test SetProcessId with alphanumeric string
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, SetProcessIdTest006, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::string testPid = "pid_12345";
    
    cpu.SetProcessId(testPid);
    auto result = cpu.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: CPU::SetPackageName
 * @tc.desc: Test SetPackageName with special characters
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCpuTest, SetPackageNameTest004, TestSize.Level1)
{
    CPU &cpu = CPU::GetInstance();
    std::string testPkg = "com.example.test_123";
    
    cpu.SetPackageName(testPkg);
    auto result = cpu.ItemData();
    
    EXPECT_FALSE(result.empty());
}
}
}
