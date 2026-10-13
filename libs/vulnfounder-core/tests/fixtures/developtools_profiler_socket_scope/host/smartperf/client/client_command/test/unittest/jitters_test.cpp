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
#include "jitters.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class SPdaemonJittersTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: Jitters::SetPackageName
 * @tc.desc: Test SetPackageName with valid package name
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, SetPackageNameTest001, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    std::string testPkg = "com.example.test";
    
    jitters.SetPackageName(testPkg);
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::SetPackageName
 * @tc.desc: Test SetPackageName with empty string
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, SetPackageNameTest002, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    std::string testPkg = "";
    
    jitters.SetPackageName(testPkg);
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::SetPackageName
 * @tc.desc: Test SetPackageName with long package name
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, SetPackageNameTest003, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    std::string testPkg = "com.very.long.package.name.for.testing.purposes";
    
    jitters.SetPackageName(testPkg);
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::SetProcessId
 * @tc.desc: Test SetProcessId with valid process ID
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, SetProcessIdTest001, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    std::string testPid = "12345";
    
    jitters.SetProcessId(testPid);
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::SetProcessId
 * @tc.desc: Test SetProcessId with empty string
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, SetProcessIdTest002, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    std::string testPid = "";
    
    jitters.SetProcessId(testPid);
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::SetProcessId
 * @tc.desc: Test SetProcessId with multiple process IDs
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, SetProcessIdTest003, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    std::string testPid = "12345 12346 12347";
    
    jitters.SetProcessId(testPid);
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::ItemData
 * @tc.desc: Test ItemData without setting package name or process ID
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, ItemDataTest001, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::ItemData
 * @tc.desc: Test ItemData with package name set
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, ItemDataTest002, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    jitters.SetPackageName("com.example.test");
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::ItemData
 * @tc.desc: Test ItemData with process ID set
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, ItemDataTest003, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    jitters.SetProcessId("12345");
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::ItemData
 * @tc.desc: Test ItemData multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, ItemDataTest004, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    jitters.SetPackageName("com.example.test");
    
    auto result1 = jitters.ItemData();
    auto result2 = jitters.ItemData();
    auto result3 = jitters.ItemData();
    
    EXPECT_FALSE(result1.empty());
    EXPECT_FALSE(result2.empty());
    EXPECT_FALSE(result3.empty());
}

/**
 * @tc.name: Jitters::StartExecutionOnce
 * @tc.desc: Test StartExecutionOnce with pause true
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, StartExecutionOnceTest001, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    
    jitters.StartExecutionOnce(true);
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::StartExecutionOnce
 * @tc.desc: Test StartExecutionOnce with pause false
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, StartExecutionOnceTest002, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    jitters.SetPackageName("com.example.test");
    
    jitters.StartExecutionOnce(false);
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::StartExecutionOnce

 @tc.desc: Test StartExecutionOnce multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, StartExecutionOnceTest003, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    jitters.SetPackageName("com.example.test");
    
    jitters.StartExecutionOnce(false);
    jitters.StartExecutionOnce(false);
    jitters.StartExecutionOnce(false);
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::GetJittersInfo
 * @tc.desc: Test GetJittersInfo returns valid info
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, GetJittersInfoTest001, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    jitters.SetPackageName("com.example.test");
    
    auto result = jitters.GetJittersInfo();
    
    EXPECT_TRUE(result.fps >= 0);
}

/**
 * @tc.name: Jitters::GetJittersInfo
 * @tc.desc: Test GetJittersInfo multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, GetJittersInfoTest002, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    jitters.SetPackageName("com.example.test");
    
    auto result1 = jitters.GetJittersInfo();
    auto result2 = jitters.GetJittersInfo();
    
    EXPECT_TRUE(result1.fps >= 0);
    EXPECT_TRUE(result2.fps >= 0);
}

/**
 * @tc.name: Jitters::GetJittersByDump
 * @tc.desc: Test GetJittersByDump with composer name
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, GetJittersByDumpTest001, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    std::string name = "composer";
    
    auto result = jitters.GetJittersByDump(name);
    
    EXPECT_TRUE(result.fps >= 0);
}

/**
 * @tc.name: Jitters::GetJittersByDump
 * @tc.desc: Test GetJittersByDump with empty name
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, GetJittersByDumpTest002, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    std::string name = "";
    
    auto result = jitters.GetJittersByDump(name);
    
    EXPECT_TRUE(result.fps >= 0);
}

/**
 * @tc.name: Jitters::GetJittersByDump
 * @tc.desc: Test GetJittersByDump with special characters
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, GetJittersByDumpTest003, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    std::string name = "composer_test";
    
    auto result = jitters.GetJittersByDump(name);
    
    EXPECT_TRUE(result.fps >= 0);
}

/**
 * @tc.name: Jitters::ItemData
 * @tc.desc: Test ItemData contains fpsJitters key
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, ItemDataTest005, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    jitters.SetPackageName("com.example.test");
    
    auto result = jitters.ItemData();
    
    EXPECT_TRUE(result.find("fpsJitters") != result.end());
}

/**
 * @tc.name: Jitters::ItemData
 * @tc.desc: Test ItemData returns NA when no package or process
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, ItemDataTest006, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    
    auto result = jitters.ItemData();
    
    EXPECT_TRUE(result.find("fpsJitters") != result.end());
}

/**
 * @tc.name: Jitters::SetPackageName
 * @tc.desc: Test SetPackageName with special characters
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, SetPackageNameTest004, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    std::string testPkg = "com.example.test_123";
    
    jitters.SetPackageName(testPkg);
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::SetProcessId
 * @tc.desc: Test SetProcessId with zero
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, SetProcessIdTest004, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    std::string testPid = "0";
    
    jitters.SetProcessId(testPid);
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::SetProcessId
 * @tc.desc: Test SetProcessId with maximum value
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, SetProcessIdTest005, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    std::string testPid = "2147483647";
    
    jitters.SetProcessId(testPid);
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::ItemData
 * @tc.desc: Test ItemData with delay between calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, ItemDataTest007, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    jitters.SetPackageName("com.example.test");
    
    auto result1 = jitters.ItemData();
    sleep(1);
    auto result2 = jitters.ItemData();
    
    EXPECT_FALSE(result1.empty());
    EXPECT_FALSE(result2.empty());
}

/**
 * @tc.name: Jitters::GetJittersInfo
 * @tc.desc: Test GetJittersInfo with delay
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, GetJittersInfoTest003, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    jitters.SetPackageName("com.example.test");
    
    auto result1 = jitters.GetJittersInfo();
    sleep(1);
    auto result2 = jitters.GetJittersInfo();
    
    EXPECT_TRUE(result1.fps >= 0);
    EXPECT_TRUE(result2.fps >= 0);
}

/**
 * @tc.name: Jitters::GetJittersByDump
 * @tc.desc: Test GetJittersByDump multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, GetJittersByDumpTest004, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    std::string name = "composer";
    
    auto result1 = jitters.GetJittersByDump(name);
    auto result2 = jitters.GetJittersByDump(name);
    
    EXPECT_TRUE(result1.fps >= 0);
    EXPECT_TRUE(result2.fps >= 0);
}

/**
 * @tc.name: Jitters::StartExecutionOnce
 * @tc.desc: Test StartExecutionOnce alternating calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, StartExecutionOnceTest004, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    jitters.SetPackageName("com.example.test");
    
    jitters.StartExecutionOnce(false);
    jitters.StartExecutionOnce(true);
    jitters.StartExecutionOnce(false);
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::SetPackageName
 * @tc.desc: Test SetPackageName multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, SetPackageNameTest005, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    
    jitters.SetPackageName("com.example.test1");
    jitters.SetPackageName("com.example.test2");
    jitters.SetPackageName("com.example.test3");
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::SetProcessId
 * @tc.desc: Test SetProcessId multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, SetProcessIdTest006, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    
    jitters.SetProcessId("12345");
    jitters.SetProcessId("12346");
    jitters.SetProcessId("12347");
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Jitters::ItemData
 * @tc.desc: Test ItemData with both package and process set
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonJittersTest, ItemDataTest008, TestSize.Level1)
{
    Jitters &jitters = Jitters::GetInstance();
    jitters.SetPackageName("com.example.test");
    jitters.SetProcessId("12345");
    
    auto result = jitters.ItemData();
    
    EXPECT_FALSE(result.empty());
}
}
}