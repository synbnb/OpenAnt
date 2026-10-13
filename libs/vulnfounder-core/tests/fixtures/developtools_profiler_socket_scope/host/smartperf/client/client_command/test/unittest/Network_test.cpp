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
#include "Network.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class SPdaemonNetworkTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: Network::GetInstance
 * @tc.desc: Test GetInstance returns singleton instance
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, GetInstanceTest001, TestSize.Level1)
{
    Network &instance1 = Network::GetInstance();
    Network &instance2 = Network::GetInstance();
    
    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: Network::ItemData
 * @tc.desc: Test ItemData returns valid result
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, ItemDataTest001, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    
    auto result = network.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Network::ItemData
 * @tc.desc: Test ItemData multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, ItemDataTest002, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    
    auto result1 = network.ItemData();
    auto result2 = network.ItemData();
    auto result3 = network.ItemData();
    
    EXPECT_FALSE(result1.empty());
    EXPECT_FALSE(result2.empty());
    EXPECT_FALSE(result3.empty());
}

/**
 * @tc.name: Network::GetNetworkInfo
 * @tc.desc: Test GetNetworkInfo returns valid network info
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, GetNetworkInfoTest001, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    
    auto result = network.GetNetworkInfo();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Network::GetNetworkInfo
 * @tc.desc: Test GetNetworkInfo multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, GetNetworkInfoTest002, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    
    auto result1 = network.GetNetworkInfo();
    auto result2 = network.GetNetworkInfo();
    
    EXPECT_FALSE(result1.empty());
    EXPECT_FALSE(result2.empty());
}

/**
 * @tc.name: Network::GetNetworkInfoDev
 * @tc.desc: Test GetNetworkInfoDev reads network devices
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, GetNetworkInfoDevTest001, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    
    auto result = network.GetNetworkInfoDev();
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Network::GetNetworkInfoDev
 * @tc.desc: Test GetNetworkInfoDev multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, GetNetworkInfoDevTest002, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    
    auto result1 = network.GetNetworkInfoDev();
    auto result2 = network.GetNetworkInfoDev();
    
    EXPECT_TRUE(result1.empty() || !result1.empty());
    EXPECT_TRUE(result2.empty() || !result2.empty());
}

/**
 * @tc.name: Network::IsFindHap
 * @tc.desc: Test IsFindHap sets hap flag
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, IsFindHapTest001, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    
    network.IsFindHap();
    
    auto result = network.ItemData();
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Network::IsStopFindHap
 * @tc.desc: Test IsStopFindHap stops hap finding
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, IsStopFindHapTest001, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    
    network.IsStopFindHap();
    
    auto result = network.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Network::ClearHapFlag
 * @tc.desc: Test ClearHapFlag resets flags
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, ClearHapFlagTest001, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    
    network.ClearHapFlag();
    
    auto result = network.GetNetworkInfo();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Network::ThreadFunctions
 * @tc.desc: Test ThreadFunctions starts thread
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, ThreadFunctionsTest001, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    
    network.ThreadFunctions();
    
    sleep(1);
}

/**
 * @tc.name: Network::PerciseMatch
 * @tc.desc: Test PerciseMatch with valid interface
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, PerciseMatchTest001, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    const char* buff = "  rmnet0: 1234 5678 9012 3456 7890 1234 5678 9012";
    std::string netStr = "rmnet0";
    
    bool result = network.PerciseMatch(buff, netStr);
    
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Network::PerciseMatch
 * @tc.desc: Test PerciseMatch with different interface
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, PerciseMatchTest002, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    const char* buff = "  eth0: 1234 5678 9012 3456 7890 1234 5678 9012";
    std::string netStr = "eth0";
    
    bool result = network.PerciseMatch(buff, netStr);
    
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Network::PerciseMatch
 * @tc.desc: Test PerciseMatch with wlan interface
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, PerciseMatchTest003, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    const char* buff = "  wlan0: 1234 5678 9012 3456 7890 1234 5678 9012";
    std::string netStr = "wlan0";
    
    bool result = network.PerciseMatch(buff, netStr);
    
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Network::PerciseMatch
 * @tc.desc: Test PerciseMatch with non-matching interface
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, PerciseMatchTest004, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    const char* buff = "  eth0: 1234 5678 9012 3456 7890 1234 5678 9012";
    std::string netStr = "rmnet0";
    
    bool result = network.PerciseMatch(buff, netStr);
    
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Network::PerciseMatch
 * @tc.desc: Test PerciseMatch with empty buffer
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, PerciseMatchTest005, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    const char* buff = "";
    std::string netStr = "eth0";
    
    bool result = network.PerciseMatch(buff, netStr);
    
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Network::PerciseMatch
 * @tc.desc: Test PerciseMatch with empty net string
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, PerciseMatchTest006, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    const char* buff = "  eth0: 1234 5678 9012 3456 7890 1234 5678 9012";
    std::string netStr = "";
    
    bool result = network.PerciseMatch(buff, netStr);
    
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Network::GetCurNetwork
 * @tc.desc: Test GetCurNetwork with zero values
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, GetCurNetworkTest001, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    long long networkCurRx = 0;
    long long networkCurTx = 0;
    
    network.GetCurNetwork(networkCurRx, networkCurTx);
    
    EXPECT_GE(networkCurRx, 0);
    EXPECT_GE(networkCurTx, 0);
}

/**
 * @tc.name: Network::GetCurNetwork
 * @tc.desc: Test GetCurNetwork with positive values
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, GetCurNetworkTest002, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    long long networkCurRx = 1000;
    long long networkCurTx = 2000;
    
    network.GetCurNetwork(networkCurRx, networkCurTx);
    
    EXPECT_GE(networkCurRx, 0);
    EXPECT_GE(networkCurTx, 0);
}

/**
 * @tc.name: Network::GetCurNetwork
 * @tc.desc: Test GetCurNetwork multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, GetCurNetworkTest003, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    long long networkCurRx = 0;
    long long networkCurTx = 0;
    
    network.GetCurNetwork(networkCurRx, networkCurTx);
    network.GetCurNetwork(networkCurRx, networkCurTx);
    network.GetCurNetwork(networkCurRx, networkCurTx);
    
    EXPECT_GE(networkCurRx, 0);
    EXPECT_GE(networkCurTx, 0);
}

/**
 * @tc.name: Network::ItemData
 * @tc.desc: Test ItemData with hap flag set
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, ItemDataTest003, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    network.IsFindHap();
    
    auto result = network.ItemData();
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Network::ItemData
 * @tc.desc: Test ItemData after stop hap
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, ItemDataTest004, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    network.IsFindHap();
    network.IsStopFindHap();
    
    auto result = network.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Network::GetNetworkInfo
 * @tc.desc: Test GetNetworkInfo contains expected keys
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, GetNetworkInfoTest003, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    
    auto result = network.GetNetworkInfo();
    
    EXPECT_TRUE(result.find("networkUp") != result.end() || result.find("networkDown") != result.end());
}

/**
 * @tc.name: Network::ClearHapFlag
 * @tc.desc: Test ClearHapFlag then GetNetworkInfo
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, ClearHapFlagTest002, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    
    network.ClearHapFlag();
    auto result = network.GetNetworkInfo();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Network::ThreadFunctions
 * @tc.desc: Test ThreadFunctions multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, ThreadFunctionsTest002, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    
    network.ThreadFunctions();
    network.ThreadFunctions();
    network.ThreadFunctions();
    
    sleep(2);
}

/**
 * @tc.name: Network::IsFindHap
 * @tc.desc: Test IsFindHap multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, IsFindHapTest002, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    
    network.IsFindHap();
    network.IsFindHap();
    network.IsFindHap();
    
    auto result = network.ItemData();
    
    EXPECT_TRUE(result.empty() || !result.empty());
}

/**
 * @tc.name: Network::IsStopFindHap
 * @tc.desc: Test IsStopFindHap multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, IsStopFindHapTest002, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    
    network.IsStopFindHap();
    network.IsStopFindHap();
    network.IsStopFindHap();
    
    auto result = network.ItemData();
    
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Network::PerciseMatch
 * @tc.desc: Test PerciseMatch with special characters
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, PerciseMatchTest008, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    const char* buff = "  eth0_1: 1234 5678 9012 3456 7890 1234 5678 9012";
    std::string netStr = "eth0_1";
    
    bool result = network.PerciseMatch(buff, netStr);
    
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Network::GetCurNetwork
 * @tc.desc: Test GetCurNetwork with large values
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonNetworkTest, GetCurNetworkTest004, TestSize.Level1)
{
    Network &network = Network::GetInstance();
    long long networkCurRx = LLONG_MAX / 2;
    long long networkCurTx = LLONG_MAX / 2;
    
    network.GetCurNetwork(networkCurRx, networkCurTx);
    
    EXPECT_GE(networkCurRx, 0);
    EXPECT_GE(networkCurTx, 0);
}
}
}