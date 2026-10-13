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
#include "Capture.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class SPdaemonCaptureTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: Capture::GetInstance
 * @tc.desc: Test GetInstance returns singleton instance
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, GetInstanceTest001, TestSize.Level1)
{
    Capture &instance1 = Capture::GetInstance();
    Capture &instance2 = Capture::GetInstance();
    
    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: Capture::SetCollectionNum
 * @tc.desc: Test SetCollectionNum resets call number
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, SetCollectionNumTest001, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    
    capture.SetCollectionNum();
    
    auto result1 = capture.ItemData();
    auto result2 = capture.ItemData();
    
    EXPECT_FALSE(result1.empty());
    EXPECT_FALSE(result2.empty());
}

/**
 * @tc.name: Capture::SocketMessage
 * @tc.desc: Test SocketMessage sets socket message flag
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, SocketMessageTest001, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    
    capture.SocketMessage();
    
    auto result = capture.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Capture::ItemData
 * @tc.desc: Test ItemData returns valid result without socket message
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, ItemDataTest001, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    capture.SetCollectionNum();
    
    auto result = capture.ItemData();
    
    EXPECT_FALSE(result.empty());
    EXPECT_GE(result.size(), 1);
}

/**
 * @tc.name: Capture::ItemData
 * @tc.desc: Test ItemData returns valid result with socket message
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, ItemDataTest002, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    capture.SetCollectionNum();
    capture.SocketMessage();
    
    auto result = capture.ItemData();
    
    EXPECT_FALSE(result.empty());
    EXPECT_GE(result.size(), 1);
}

/**
 * @tc.name: Capture::ItemData
 * @tc.desc: Test ItemData multiple calls without socket message
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, ItemDataTest003, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    capture.SetCollectionNum();
    
    auto result1 = capture.ItemData();
    auto result2 = capture.ItemData();
    auto result3 = capture.ItemData();
    
    EXPECT_FALSE(result1.empty());
    EXPECT_FALSE(result2.empty());
    EXPECT_FALSE(result3.empty());
}

/**
 * @tc.name: Capture::ItemData
 * @tc.desc: Test ItemData multiple calls with socket message
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, ItemDataTest004, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    capture.SetCollectionNum();
    capture.SocketMessage();
    
    auto result1 = capture.ItemData();
    auto result2 = capture.ItemData();
    auto result3 = capture.ItemData();
    
    EXPECT_FALSE(result1.empty());
    EXPECT_FALSE(result2.empty());
    EXPECT_FALSE(result3.empty());
}

/**
 * @tc.name: Capture::ItemData
 * @tc.desc: Test ItemData with alternating calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, ItemDataTest005, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    capture.SetCollectionNum();
    
    auto result1 = capture.ItemData();
    capture.SocketMessage();
    auto result2 = capture.ItemData();
    capture.SetCollectionNum();
    auto result3 = capture.ItemData();
    
    EXPECT_FALSE(result1.empty());
    EXPECT_FALSE(result2.empty());
    EXPECT_FALSE(result3.empty());
}

/**
 * @tc.name: Capture::GetCurTimes
 * @tc.desc: Test GetCurTimes returns valid timestamp
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, GetCurTimesTest001, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    
    long long time1 = capture.GetCurTimes();
    long long time2 = capture.GetCurTimes();
    
    EXPECT_GT(time1, 0);
    EXPECT_GE(time2, time1);
}

/**
 * @tc.name: Capture::GetCurTimes
 * @tc.desc: Test GetCurTimes multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, GetCurTimesTest002, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    
    for (int i = 0; i < 10; i++) {
        long long time = capture.GetCurTimes();
        EXPECT_GT(time, 0);
    }
}

/**
 * @tc.name: Capture::TriggerGetCatch
 * @tc.desc: Test TriggerGetCatch starts thread
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, TriggerGetCatchTest001, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    
    capture.TriggerGetCatch();
    
    sleep(1);
}

/**
 * @tc.name: Capture::TriggerGetCatchSocket
 * @tc.desc: Test TriggerGetCatchSocket starts thread
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, TriggerGetCatchSocketTest001, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    
    capture.TriggerGetCatchSocket();
    
    sleep(1);
}

/**
 * @tc.name: Capture::TakeScreenCap
 * @tc.desc: Test TakeScreenCap with valid path
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, TakeScreenCapTest001, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    std::string savePath = "/data/local/tmp/test_capture.png";
    
    bool result = capture.TakeScreenCap(savePath);
    
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Capture::TakeScreenCap
 * @tc.desc: Test TakeScreenCap with empty path
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, TakeScreenCapTest002, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    std::string savePath = "";
    
    bool result = capture.TakeScreenCap(savePath);
    
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Capture::TakeScreenCap
 * @tc.desc: Test TakeScreenCap with long path
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, TakeScreenCapTest003, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    std::string savePath = "/data/local/tmp/very_long_file_name_for_testing_purposes_that_exceeds_normal_length.png";
    
    bool result = capture.TakeScreenCap(savePath);
    
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Capture::TakeScreenCap
 * @tc.desc: Test TakeScreenCap with special characters in path
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, TakeScreenCapTest004, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    std::string savePath = "/data/local/tmp/test_capture_123.png";
    
    bool result = capture.TakeScreenCap(savePath);
    
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Capture::TakeScreenCap
 * @tc.desc: Test TakeScreenCap multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, TakeScreenCapTest005, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    
    bool result1 = capture.TakeScreenCap("/data/local/tmp/test1.png");
    bool result2 = capture.TakeScreenCap("/data/local/tmp/test2.png");
    bool result3 = capture.TakeScreenCap("/data/local/tmp/test3.png");
    
    EXPECT_FALSE(result1);
    EXPECT_FALSE(result2);
    EXPECT_FALSE(result3);
}

/**
 * @tc.name: Capture::ItemData
 * @tc.desc: Test ItemData contains capture key
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, ItemDataTest006, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    capture.SetCollectionNum();
    
    auto result = capture.ItemData();
    
    EXPECT_TRUE(result.find("capture") != result.end());
}

/**
 * @tc.name: Capture::ItemData
 * @tc.desc: Test ItemData with socket message contains capture key
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, ItemDataTest007, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    capture.SetCollectionNum();
    capture.SocketMessage();
    
    auto result = capture.ItemData();
    
    EXPECT_TRUE(result.find("capture") != result.end());
}

/**
 * @tc.name: Capture::SetCollectionNum
 * @tc.desc: Test SetCollectionNum then ItemData behavior
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, SetCollectionNumTest002, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    
    capture.SetCollectionNum();
    auto result1 = capture.ItemData();
    
    capture.SetCollectionNum();
    auto result2 = capture.ItemData();
    
    EXPECT_FALSE(result1.empty());
    EXPECT_FALSE(result2.empty());
}

/**
 * @tc.name: Capture::SocketMessage
 * @tc.desc: Test SocketMessage multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, SocketMessageTest002, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    
    capture.SocketMessage();
    capture.SocketMessage();
    capture.SocketMessage();
    
    auto result = capture.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Capture::TriggerGetCatch
 * @tc.desc: Test TriggerGetCatch multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, TriggerGetCatchTest002, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    
    capture.TriggerGetCatch();
    capture.TriggerGetCatch();
    capture.TriggerGetCatch();
    
    sleep(2);
}

/**
 * @tc.name: Capture::TriggerGetCatchSocket
 * @tc.desc: Test TriggerGetCatchSocket multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, TriggerGetCatchSocketTest002, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    
    capture.TriggerGetCatchSocket();
    capture.TriggerGetCatchSocket();
    capture.TriggerGetCatchSocket();
    
    sleep(2);
}

/**
 * @tc.name: Capture::ItemData
 * @tc.desc: Test ItemData returns different paths on different calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, ItemDataTest008, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    capture.SetCollectionNum();
    
    auto result1 = capture.ItemData();
    auto result2 = capture.ItemData();
    
    EXPECT_FALSE(result1.empty());
    EXPECT_FALSE(result2.empty());
}

/**
 * @tc.name: Capture::TakeScreenCap
 * @tc.desc: Test TakeScreenCap with invalid directory path
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, TakeScreenCapTest006, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    std::string savePath = "/invalid/path/test_capture.png";
    
    bool result = capture.TakeScreenCap(savePath);
    
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Capture::TakeScreenCap
 * @tc.desc: Test TakeScreenCap with relative path
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, TakeScreenCapTest007, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    std::string savePath = "test_capture.png";
    
    bool result = capture.TakeScreenCap(savePath);
    
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Capture::GetCurTimes
 * @tc.desc: Test GetCurTimes returns increasing values
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonCaptureTest, GetCurTimesTest003, TestSize.Level1)
{
    Capture &capture = Capture::GetInstance();
    
    long long time1 = capture.GetCurTimes();
    sleep(1);
    long long time2 = capture.GetCurTimes();
    
    EXPECT_GT(time2, time1);
}
}
}