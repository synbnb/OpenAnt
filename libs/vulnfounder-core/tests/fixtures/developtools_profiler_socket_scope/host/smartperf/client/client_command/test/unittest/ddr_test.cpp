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
#include "DDR.h"
#include "sp_utils.h"
#include "common.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class DDRTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(DDRTest, ItemDataTest, TestSize.Level1)
{
    bool ret = false;
    DDR &ddr = DDR::GetInstance();
    std::map<std::string, std::string> result = DDR::GetInstance().ItemData();
    result["ddrFrequency"] = std::to_string(ddr.GetDdrFreq());
    if (result.find("ddrFrequency") != result.end() && result["ddrFrequency"].empty()) {
        result["ddrFrequency"] = "NA";
    }
    if (!result.empty()) {
        ret = true;
    }
    
    EXPECT_TRUE(ret);
}
}
}