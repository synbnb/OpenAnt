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
#include <iostream>
#include "sp_utils.h"
#include "Power.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class PowerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}

    const std::string currentNowPath = "/sys/class/power_supply/Battery/current_now";
    const std::string voltageNowPath = "/sys/class/power_supply/Battery/voltage_now";
};

HWTEST_F(PowerTest, PowerTestCase02, TestSize.Level1)
{
    Power &power = Power::GetInstance();
    power.SetRkFlag();
    std::map<std::string, std::string> result = power.ItemData();
    EXPECT_EQ(result["failed"], "RK does not support power acquisition");
}
}
}