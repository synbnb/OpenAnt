/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "sp_utils.h"
#include "parse_radar.h"
#include <string>
#include <vector>

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class ParseRadarTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(ParseRadarTest, ParseRadarAPPStartTest, TestSize.Level1)
{
    bool ret = false;
    std::string target = "\"ANIMATION_LATENCY\":";
    std::string target1 = "\"E2E_LATENCY\":";
    std::string target2 = "\"RESPONSE_LATENCY\":";
    std::string target3 = "\"FIRST_FRAEM_DRAWN_LATENCY\":";
    std::string animationCompleteTime = "\"ANIMATION_LATENCY\":608";
    std::string comepleteTime = "\"E2E_LATENCY\":686";
    std::string responseTime = "\"RESPONSE_LATENCY\":189";
    std::string firstFrameDrawnTime = "\"FIRST_FRAEM_DRAWN_LATENCY\":182";
    OHOS::SmartPerf::ParseRadar parseRadar;
    std::string result = parseRadar.ExtractString(animationCompleteTime, target);
    std::string result1 = parseRadar.ExtractString(comepleteTime, target1);
    std::string result2 = parseRadar.ExtractString(responseTime, target2);
    std::string result3 = parseRadar.ExtractString(firstFrameDrawnTime, target3);
    if (!result.empty() && !result1.empty() && !result2.empty() && !result3.empty()) {
        ret = true;
    }

    EXPECT_TRUE(ret);
}

HWTEST_F(ParseRadarTest, ParseRadarDelayTimeTest, TestSize.Level1)
{
    bool ret = false;
    std::string responseTime = "{\"RESPONSE_LATENCY\":189,\"level\":\"MINOR\"}";
    int delayTime = 1000;
    std::string target = "\"RESPONSE_LATENCY\"";
    OHOS::SmartPerf::ParseRadar parseRadar;
    double result = parseRadar.ParseRadarDelayTime(responseTime, target, delayTime);
    if (result > 0) {
        ret = true;
    }

    EXPECT_TRUE(ret);
}
}
}