/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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
#include "navigation.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class NavigationTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NavigationTest::SetUpTestCase(void)
{
}

void NavigationTest::TearDownTestCase(void)
{
}

void NavigationTest::SetUp()
{
}

void NavigationTest::TearDown()
{
}

/**
 * @tc.name: NavigationTest_SetProcessId_001
 * @tc.desc: 验证 SetProcessId 设置有效的进程ID
 * @tc.type: FUNC
 */
HWTEST_F(NavigationTest, NavigationTest_SetProcessId_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NavigationTest-begin NavigationTest_SetProcessId_001";
    Navigation &navigation = Navigation::GetInstance();
    std::string testPid = "12345";
    navigation.SetProcessId(testPid);
    std::map<std::string, std::string> result = navigation.ItemData();
    EXPECT_TRUE(result.count("navPathName") > 0);
    GTEST_LOG_(INFO) << "NavigationTest-end NavigationTest_SetProcessId_001";
}

/**
 * @tc.name: NavigationTest_SetProcessId_002
 * @tc.desc: 验证 SetProcessId 设置空进程ID
 * @tc.type: FUNC
 */
HWTEST_F(NavigationTest, NavigationTest_SetProcessId_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NavigationTest-begin NavigationTest_SetProcessId_002";
    Navigation &navigation = Navigation::GetInstance();
    std::string emptyPid = "";
    navigation.SetProcessId(emptyPid);
    std::map<std::string, std::string> result = navigation.ItemData();
    EXPECT_TRUE(result.count("navPathName") > 0);
    GTEST_LOG_(INFO) << "NavigationTest-end NavigationTest_SetProcessId_002";
}

/**
 * @tc.name: NavigationTest_SetProcessId_003
 * @tc.desc: 验证 SetProcessId 设置不存在的进程ID
 * @tc.type: FUNC
 */
HWTEST_F(NavigationTest, NavigationTest_SetProcessId_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NavigationTest-begin NavigationTest_SetProcessId_003";
    Navigation &navigation = Navigation::GetInstance();
    std::string nonExistentPid = "999999999";
    
    navigation.SetProcessId(nonExistentPid);
    
    std::map<std::string, std::string> result = navigation.ItemData();
    EXPECT_TRUE(result.count("navPathName") > 0);
    GTEST_LOG_(INFO) << "NavigationTest-end NavigationTest_SetProcessId_003";
}

/**
 * @tc.name: NavigationTest_GetInstance_001
 * @tc.desc: 验证 GetInstance 返回单例实例
 * @tc.type: FUNC
 */
HWTEST_F(NavigationTest, NavigationTest_GetInstance_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NavigationTest-begin NavigationTest_GetInstance_001";
    Navigation &instance1 = Navigation::GetInstance();
    Navigation &instance2 = Navigation::GetInstance();
    
    EXPECT_EQ(&instance1, &instance2);
    GTEST_LOG_(INFO) << "NavigationTest-end NavigationTest_GetInstance_001";
}

/**
 * @tc.name: NavigationTest_ItemData_001
 * @tc.desc: 验证 ItemData 返回包含预期键值的map
 * @tc.type: FUNC
 */
HWTEST_F(NavigationTest, NavigationTest_ItemData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NavigationTest-begin NavigationTest_ItemData_001";
    Navigation &navigation = Navigation::GetInstance();
    navigation.SetProcessId("12345");
    
    std::map<std::string, std::string> result = navigation.ItemData();
    
    EXPECT_TRUE(result.count("navPathName") > 0);
    EXPECT_TRUE(result.size() >= 1);
    GTEST_LOG_(INFO) << "NavigationTest-end NavigationTest_ItemData_001";
}

/**
 * @tc.name: NavigationTest_ItemData_002
 * @tc.desc: 验证 ItemData 处理空进程ID的情况
 * @tc.type: FUNC
 */
HWTEST_F(NavigationTest, NavigationTest_ItemData_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NavigationTest-begin NavigationTest_ItemData_002";
    Navigation &navigation = Navigation::GetInstance();
    navigation.SetProcessId("");
    
    std::map<std::string, std::string> result = navigation.ItemData();
    
    EXPECT_TRUE(result.count("navPathName") > 0);
    GTEST_LOG_(INFO) << "NavigationTest-end NavigationTest_ItemData_002";
}

/**
 * @tc.name: NavigationTest_ItemData_003
 * @tc.desc: 验证 ItemData 多次调用的稳定性
 * @tc.type: FUNC
 */
HWTEST_F(NavigationTest, NavigationTest_ItemData_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NavigationTest-begin NavigationTest_ItemData_003";
    Navigation &navigation = Navigation::GetInstance();
    navigation.SetProcessId("12345");
    
    std::map<std::string, std::string> result1 = navigation.ItemData();
    std::map<std::string, std::string> result2 = navigation.ItemData();
    
    EXPECT_TRUE(result1.count("navPathName") > 0);
    EXPECT_TRUE(result2.count("navPathName") > 0);
    GTEST_LOG_(INFO) << "NavigationTest-end NavigationTest_ItemData_003";
}
}
}
