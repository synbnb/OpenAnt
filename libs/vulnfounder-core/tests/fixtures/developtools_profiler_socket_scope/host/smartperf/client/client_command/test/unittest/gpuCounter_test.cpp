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
#include <thread>
#include <gtest/gtest.h>
#include <unistd.h>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <chrono>
#include "lock_frequency.h"
#include "GpuCounter.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class SPdaemonLockFrequencyTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: LockFrequency::ItemData
 * @tc.desc: Test ItemData
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonLockFrequencyTest, ItemDataTestCase, TestSize.Level1)
{
    std::map<std::string, std::string> result = LockFrequency::GetInstance().ItemData();
    EXPECT_EQ(result.size(), 0);
}

/**
 * @tc.name: LockFrequency::LockingThread
 * @tc.desc: Test LockingThread
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonLockFrequencyTest, LockingThreadTestCase, TestSize.Level1)
{
    LockFrequency::GetInstance().SetIsCollecting(true);
    std::thread lock = std::thread([this]() {
        LockFrequency::GetInstance().LockingThread();
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    LockFrequency::GetInstance().SetIsCollecting(false);
    lock.join();
}
}
}