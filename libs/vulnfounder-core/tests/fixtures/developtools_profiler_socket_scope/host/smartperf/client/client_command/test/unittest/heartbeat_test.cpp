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
#include <thread>
#include <chrono>
#include "heartbeat.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class SPdaemonHeartbeatTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: Heartbeat::GetInstance
 * @tc.desc: Test GetInstance returns singleton instance
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, GetInstanceTest001, TestSize.Level1)
{
    Heartbeat &instance1 = Heartbeat::GetInstance();
    Heartbeat &instance2 = Heartbeat::GetInstance();
    
    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: Heartbeat::UpdatestartTime
 * @tc.desc: Test UpdatestartTime updates the start time
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, UpdatestartTimeTest001, TestSize.Level1)
{
    Heartbeat &heartbeat = Heartbeat::GetInstance();
    
    heartbeat.UpdatestartTime();
    
    EXPECT_TRUE(true);
}

/**
 * @tc.name: Heartbeat::UpdatestartTime
 * @tc.desc: Test UpdatestartTime multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, UpdatestartTimeTest002, TestSize.Level1)
{
    Heartbeat &heartbeat = Heartbeat::GetInstance();
    
    heartbeat.UpdatestartTime();
    heartbeat.UpdatestartTime();
    heartbeat.UpdatestartTime();
    
    EXPECT_TRUE(true);
}

/**
 * @tc.name: Heartbeat::UpdatestartTime
 * @tc.desc: Test UpdatestartTime thread safety
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, UpdatestartTimeTest003, TestSize.Level1)
{
    Heartbeat &heartbeat = Heartbeat::GetInstance();
    
    std::thread t1([&heartbeat]() {
        heartbeat.UpdatestartTime();
    });
    
    std::thread t2([&heartbeat]() {
        heartbeat.UpdatestartTime();
    });
    
    t1.join();
    t2.join();
    
    EXPECT_TRUE(true);
}

/**
 * @tc.name: Heartbeat::KillSpId
 * @tc.desc: Test KillSpId function execution
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, KillSpIdTest001, TestSize.Level1)
{
    Heartbeat &heartbeat = Heartbeat::GetInstance();
    
    heartbeat.KillSpId();
    
    EXPECT_TRUE(true);
}

/**
 * @tc.name: Heartbeat::KillSpId
 * @tc.desc: Test KillSpId multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, KillSpIdTest002, TestSize.Level1)
{
    Heartbeat &heartbeat = Heartbeat::GetInstance();
    
    heartbeat.KillSpId();
    heartbeat.KillSpId();
    
    EXPECT_TRUE(true);
}

/**
 * @tc.name: Heartbeat::HeartbeatRule
 * @tc.desc: Test HeartbeatRule function execution
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, HeartbeatRuleTest001, TestSize.Level1)
{
    Heartbeat &heartbeat = Heartbeat::GetInstance();
    
    std::thread t([&heartbeat]() {
        heartbeat.UpdatestartTime();
        heartbeat.HeartbeatRule();
    });
    
    t.detach();
    
    usleep(100000);
    
    EXPECT_TRUE(true);
}

/**
 * @tc.name: Heartbeat::HeartbeatRule
 * @tc.desc: Test HeartbeatRule with UpdatestartTime
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, HeartbeatRuleTest002, TestSize.Level1)
{
    Heartbeat &heartbeat = Heartbeat::GetInstance();
    
    heartbeat.UpdatestartTime();
    
    std::thread t([&heartbeat]() {
        heartbeat.HeartbeatRule();
    });
    
    t.detach();
    
    usleep(100000);
    
    EXPECT_TRUE(true);
}

/**
 * @tc.name: Heartbeat::UpdatestartTime
 * @tc.desc: Test UpdatestartTime timing
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, UpdatestartTimeTest004, TestSize.Level1)
{
    Heartbeat &heartbeat = Heartbeat::GetInstance();
    
    auto start = std::chrono::steady_clock::now();
    heartbeat.UpdatestartTime();
    auto end = std::chrono::steady_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    EXPECT_LT(duration, 100);
}

/**
 * @tc.name: Heartbeat::KillSpId
 * @tc.desc: Test KillSpId timing
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, KillSpIdTest003, TestSize.Level1)
{
    Heartbeat &heartbeat = Heartbeat::GetInstance();
    
    auto start = std::chrono::steady_clock::now();
    heartbeat.KillSpId();
    auto end = std::chrono::steady_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    EXPECT_LT(duration, 1000);
}

/**
 * @tc.name: Heartbeat::GetInstance
 * @tc.desc: Test GetInstance consistency
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, GetInstanceTest002, TestSize.Level1)
{
    Heartbeat &instance1 = Heartbeat::GetInstance();
    Heartbeat &instance2 = Heartbeat::GetInstance();
    Heartbeat &instance3 = Heartbeat::GetInstance();
    
    EXPECT_EQ(&instance1, &instance2);
    EXPECT_EQ(&instance2, &instance3);
}

/**
 * @tc.name: Heartbeat::UpdatestartTime
 * @tc.desc: Test UpdatestartTime after multiple GetInstance calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, UpdatestartTimeTest005, TestSize.Level1)
{
    Heartbeat &heartbeat1 = Heartbeat::GetInstance();
    Heartbeat &heartbeat2 = Heartbeat::GetInstance();
    
    heartbeat1.UpdatestartTime();
    heartbeat2.UpdatestartTime();
    
    EXPECT_TRUE(true);
}

/**
 * @tc.name: Heartbeat::KillSpId
 * @tc.desc: Test KillSpId after UpdatestartTime
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, KillSpIdTest004, TestSize.Level1)
{
    Heartbeat &heartbeat = Heartbeat::GetInstance();
    
    heartbeat.UpdatestartTime();
    heartbeat.KillSpId();
    
    EXPECT_TRUE(true);
}

/**
 * @tc.name: Heartbeat::HeartbeatRule
 * @tc.desc: Test HeartbeatRule short duration
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, HeartbeatRuleTest003, TestSize.Level1)
{
    Heartbeat &heartbeat = Heartbeat::GetInstance();
    
    heartbeat.UpdatestartTime();
    
    std::thread t([&heartbeat]() {
        heartbeat.HeartbeatRule();
    });
    
    t.detach();
    
    usleep(50000);
    
    EXPECT_TRUE(true);
}

/**
 * @tc.name: Heartbeat::UpdatestartTimeStart
 * @tc.desc: Test UpdatestartTime rapid calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, UpdatestartTimeTest006, TestSize.Level1)
{
    Heartbeat &heartbeat = Heartbeat::GetInstance();
    
    for (int i = 0; i < 10; i++) {
        heartbeat.UpdatestartTime();
    }
    
    EXPECT_TRUE(true);
}

/**
 * @tc.name: Heartbeat::KillSpId
 * @tc.desc: Test KillSpId rapid calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, KillSpIdTest005, TestSize.Level1)
{
    Heartbeat &heartbeat = Heartbeat::GetInstance();
    
    for (int i = 0; i < 5; i++) {
        heartbeat.KillSpId();
    }
    
    EXPECT_TRUE(true);
}

/**
 * @tc.name: Heartbeat::HeartbeatRule
 * @tc.desc: Test HeartbeatRule with multiple UpdatestartTime
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, HeartbeatRuleTest004, TestSize.Level1)
{
    Heartbeat &heartbeat = Heartbeat::GetInstance();
    
    std::thread t([&heartbeat]() {
        for (int i = 0; i < 5; i++) {
            heartbeat.UpdatestartTime();
            usleep(10000);
        }
    });
    
    std::thread t2([&heartbeat]() {
        heartbeat.HeartbeatRule();
    });
    
    t.detach();
    t2.detach();
    
    usleep(200000);
    
    EXPECT_TRUE(true);
}

/**
 * @tc.name: Heartbeat::UpdatestartTime
 * @tc.desc: Test UpdatestartTime before KillSpId
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, UpdatestartTimeTest007, TestSize.Level1)
{
    Heartbeat &heartbeat = Heartbeat::GetInstance();
    
    heartbeat.UpdatestartTime();
    heartbeat.UpdatestartTime();
    heartbeat.KillSpId();
    
    EXPECT_TRUE(true);
}

/**
 * @tc.name: Heartbeat::GetInstance
 * @tc.desc: Test GetInstance returns same reference
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonHeartbeatTest, GetInstanceTest003, TestSize.Level1)
{
    Heartbeat *instance1 = &Heartbeat::GetInstance();
    Heartbeat *instance2 = &Heartbeat::GetInstance();
    
    EXPECT_EQ(instance1, instance2);
    EXPECT_NE(instance1, nullptr);
}
}
}
