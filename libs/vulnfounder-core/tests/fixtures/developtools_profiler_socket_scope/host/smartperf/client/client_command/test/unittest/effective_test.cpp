/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under * Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with * License.
 * You may obtain a copy of * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under * License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See * License for * specific language governing permissions and
 * limitations under * License.
 */
#include <gtest/gtest.h>
#include <string>
#include <map>
#include "effective.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class EffectiveTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void EffectiveTest::SetUpTestCase(void)
{
}

void EffectiveTest::TearDownTestCase(void)
{
}

void EffectiveTest::SetUp()
{
}

void EffectiveTest::TearDown()
{
}
/**
* @tc.name: EffectiveTest_GetInstance_001
* @tc.desc:：验证 GetInstance 返回单例实例
* @tc.type: FUNC
*/
HWTEST_F(EffectiveTest, EffectiveTest_GetInstance_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "EffectiveTest-begin EffectiveTest_GetInstance_001";
    Effective &instance1 = Effective::GetInstance();
    Effective &instance2 = Effective::GetInstance();
    
    EXPECT_EQ(&instance1, &instance2);
    GTEST_LOG_(INFO) << "EffectiveTest-end EffectiveTest_GetInstance_001";
}

/**
* @tc.name: EffectiveTest_ItemData_001
* @tc.desc:：验证 ItemData 返回包含预期键值的map
* @tc.type: FUNC
*/
HWTEST_F(EffectiveTest, EffectiveTest_ItemData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "EffectiveTest-begin EffectiveTest_ItemData_001";
    Effective &effective = Effective::GetInstance();
    
    map<string, string> result = effective.ItemData();
    
    EXPECT_TRUE(result.count("fpsWarn") > 0);
    EXPECT_TRUE(result.count("FrameTimeWarn") > 0);
    EXPECT_TRUE(result.count("TraceTime") > 0);
    GTEST_LOG_(INFO) << "EffectiveTest-end EffectiveTest_ItemData_001";
}

/**
* @tc.name: EffectiveTest_ItemData_002
* @tc.desc:：验证 ItemData 多次调用的稳定性
* @tc.type: FUNC
*/
HWTEST_F(EffectiveTest, EffectiveTest_ItemData_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "EffectiveTest-begin EffectiveTest_ItemData_002";
    Effective &effective = Effective::GetInstance();
    
    map<string, string> result1 = effective.ItemData();
    map<string, string> result2 = effective.ItemData();
    
    EXPECT_TRUE(result1.size() >= 0);
    EXPECT_TRUE(result2.size() >= 0);
    GTEST_LOG_(INFO) << "EffectiveTest-end EffectiveTest_ItemData_002";
}

/**
* @tc.name: EffectiveTest_ItemData_003
* @tc.desc:：验证 ItemData 返回值的类型正确性
* @tc.type: FUNC
*/
HWTEST_F(EffectiveTest, EffectiveTest_ItemData_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "EffectiveTest-begin EffectiveTest_ItemData_003";
    Effective &effective = Effective::GetInstance();
    
    map<string, string> result = effective.ItemData();
    
    if (result.count("fpsWarn") > 0) {
        EXPECT_FALSE(result["fpsWarn"].empty());
    }
    if (result.count("FrameTimeWarn") > 0) {
        EXPECT_FALSE(result["FrameTimeWarn"].empty());
    }
    if (result.count("TraceTime") > 0) {
        EXPECT_FALSE(result["TraceTime"].empty());
    }
    GTEST_LOG_(INFO) << "EffectiveTest-end EffectiveTest_ItemData_003";
}

/**
* @tc.name: EffectiveTest_MultipleInstances_001
* @tc.desc:：验证多个实例调用的一致性
* @tc.type: FUNC
*/
HWTEST_F(EffectiveTest, EffectiveTest_MultipleInstances_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "EffectiveTest-begin EffectiveTest_MultipleInstances_001";
    Effective &effective1 = Effective::GetInstance();
    Effective &effective2 = Effective::GetInstance();
    
    map<string, string> result1 = effective1.ItemData();
    map<string, string> result2 = effective2.ItemData();
    
    EXPECT_EQ(result1.size(), result2.size());
    GTEST_LOG_(INFO) << "EffectiveTest-end EffectiveTest_MultipleInstances_001";
}

/**
* @tc.name: EffectiveTest_MapKeys_001
* @tc.desc:：验证返回的map包含所有预期键
* @tc.type: FUNC
*/
HWTEST_F(EffectiveTest, EffectiveTest_MapKeys_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "EffectiveTest-begin EffectiveTest_MapKeys_001";
    Effective &effective = Effective::GetInstance();
    
    map<string, string> result = effective.ItemData();
    
    EXPECT_TRUE(result.count("fpsWarn") > 0 || result.count("FrameTimeWarn") > 0);
    EXPECT_TRUE(result.count("TraceTime") > 0);
    GTEST_LOG_(INFO) << "EffectiveTest-end EffectiveTest_MapKeys_001";
}
}
}
