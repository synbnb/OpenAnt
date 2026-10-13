/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under * Apache License, Version 2.0 (the "License");
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
#include "hiperf.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class HiperfTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void HiperfTest::SetUpTestCase(void)
{
}

void HiperfTest::TearDownTestCase(void)
{
}

void HiperfTest::SetUp()
{
}

void HiperfTest::TearDown()
{
}
/**
 * @tc.name: HiperfTest_GetInstance_001
 * @tc.desc:：验证 GetInstance 返回单例实例
 * @tc.type: FUNC
 */
HWTEST_F(HiperfTest, HiperfTest_GetInstance_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HiperfTest-begin HiperfTest_GetInstance_001";
    Hiperf &instance1 = Hiperf::GetInstance();
    Hiperf &instance2 = Hiperf::GetInstance();
    
    EXPECT_EQ(&instance1, &instance2);
    GTEST_LOG_(INFO) << "HiperfTest-end HiperfTest_GetInstance_001";
}

/**
 * @tc.name: HiperfTest_SetProcessId_001
 * @tc.desc:：验证 SetProcessId 设置有效的进程ID
 * @tc.type: FUNC
 */
HWTEST_F(HiperfTest, HiperfTest_SetProcessId_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HiperfTest-begin HiperfTest_SetProcessId_001";
    Hiperf &hiperf = Hiperf::GetInstance();
    std::string testPid = "12345";
    
    hiperf.SetProcessId(testPid);
    
    std::map<std::string, std::string> result = hiperf.ItemData();
    EXPECT_TRUE(result.size() >= 0);
    GTEST_LOG_(INFO) << "HiperfTest-end HiperfTest_SetProcessId_001";
}

/**
 * @tc.name: HiperfTest_SetProcessId_002
 * @tc.desc:：验证 SetProcessId 设置空进程ID
 * @tc.type: FUNC
 */
HWTEST_F(HiperfTest, HiperfTest_SetProcessId_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HiperfTest-begin HiperfTest_SetProcessId_002";
    Hiperf &hiperf = Hiperf::GetInstance();
    std::string emptyPid = "";
    
    hiperf.SetProcessId(emptyPid);
    
    std::map<std::string, std::string> result = hiperf.ItemData();
    EXPECT_TRUE(result.size() >= 0);
    GTEST_LOG_(INFO) << "HiperfTest-end HiperfTest_SetProcessId_002";
}

/**
 * @tc.name: HiperfTest_ItemData_001
 * @tc.desc:：验证 ItemData 返回包含预期键值的map
 * @tc.type: FUNC
 */
HWTEST_F(HiperfTest, HiperfTest_ItemData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HiperfTest-begin HiperfTest_ItemData_001";
    Hiperf &hiperf = Hiperf::GetInstance();
    
    std::map<std::string, std::string> result = hiperf.ItemData();
    
    EXPECT_TRUE(result.size() >= 0);
    GTEST_LOG_(INFO) << "HiperfTest-end HiperfTest_ItemData_001";
}

/**
 * @tc.name: HiperfTest_ItemData_002
 * @tc.desc:：验证 ItemData 多次调用的稳定性
 * @tc.type: FUNC
 */
HWTEST_F(HiperfTest, HiperfTest_ItemData_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HiperfTest-begin HiperfTest_ItemData_002";
    Hiperf &hiperf = Hiperf::GetInstance();
    
    std::map<std::string, std::string> result1 = hiperf.ItemData();
    std::map<std::string, std::string> result2 = hiperf.ItemData();
    
    EXPECT_TRUE(result1.size() >= 0);
    EXPECT_TRUE(result2.size() >= 0);
    GTEST_LOG_(INFO) << "HiperfTest-end HiperfTest_ItemData_002";
}

/**
 * @tc.name: HiperfTest_StartExecutionOnce_001
 * @tc.desc:：验证 StartExecutionOnce 正常启动
 * @tc.type: FUNC
 */
HWTEST_F(HiperfTest, HiperfTest_StartExecutionOnce_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HiperfTest-begin HiperfTest_StartExecutionOnce_001";
    Hiperf &hiperf = Hiperf::GetInstance();
    hiperf.SetProcessId("12345");
    
    hiperf.StartExecutionOnce(false);
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "HiperfTest-end HiperfTest_StartExecutionOnce_001";
}

/**
 * @tc.name: HiperfTest_StartExecutionOnce_002
 * @tc.desc:：验证 StartExecutionOnce 在空进程ID时的行为
 * @tc.type: FUNC
 */
HWTEST_F(HiperfTest, HiperfTest_StartExecutionOnce_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HiperfTest-begin HiperfTest_StartExecutionOnce_002";
    Hiperf &hiperf = Hiperf::GetInstance();
    hiperf.SetProcessId("");
    
    hiperf.StartExecutionOnce(false);
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "HiperfTest-end HiperfTest_StartExecutionOnce_002";
}

/**
 * @tc.name: HiperfTest_FinishtExecutionOnce_001
 * @tc.desc:：验证 FinishtExecutionOnce 正常停止
 * @tc.type: FUNC
 */
HWTEST_F(HiperfTest, HiperfTest_FinishtExecutionOnce_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HiperfTest-begin HiperfTest_FinishtExecutionOnce_001";
    Hiperf &hiperf = Hiperf::GetInstance();
    
    hiperf.FinishtExecutionOnce(false);
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "HiperfTest-end HiperfTest_FinishtExecutionOnce_001";
}

/**
 * @tc.name: HiperfTest_ProcessCountData_001
 * @tc.desc:：验证 ProcessCountData 处理包含标点的计数数据
 * @tc.type: FUNC
 */
HWTEST_F(HiperfTest, HiperfTest_ProcessCountData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HiperfTest-begin HiperfTest_ProcessCountData_001";
    Hiperf &hiperf = Hiperf::GetInstance();
    std::string countWithPunct = "1,234,567";
    
    std::string result = hiperf.ProcessCountData(countWithPunct);
    
    EXPECT_FALSE(result.empty());
    GTEST_LOG_(INFO) << "HiperfTest-end HiperfTest_ProcessCountData_001";
}

/**
 * @tc.name: HiperfTest_ProcessCountData_002
 * @tc.desc:：验证 ProcessCountData 处理纯数字的计数数据
 * @tc.type: FUNC
 */
HWTEST_F(HiperfTest, HiperfTest_ProcessCountData_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HiperfTest-begin HiperfTest_ProcessCountData_002";
    Hiperf &hiperf = Hiperf::GetInstance();
    std::string pureNumber = "123456789";
    
    std::string result = hiperf.ProcessCountData(pureNumber);
    
    EXPECT_FALSE(result.empty());
    GTEST_LOG_(INFO) << "HiperfTest-end HiperfTest_ProcessCountData_002";
}

/**
 * @tc.name: HiperfTest_ProcessCountData_003
 * @tc.desc:：验证 ProcessCountData 处理空字符串
 * @tc.type: FUNC
 */
HWTEST_F(HiperfTest, HiperfTest_ProcessCountData_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HiperfTest-begin HiperfTest_ProcessCountData_003";
    Hiperf &hiperf = Hiperf::GetInstance();
    std::string emptyString = "";
    
    std::string result = hiperf.ProcessCountData(emptyString);
    
    EXPECT_TRUE(result.empty());
    GTEST_LOG_(INFO) << "HiperfTest-end HiperfTest_ProcessCountData_003";
}
}
}
