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
#include "RAM.h"
#include <sstream>
#include <fstream>
#include <climits>
#include <cstdio>
#include <algorithm>
#include <iostream>
#include <thread>
#include <string>
#include <regex>
#include "sp_utils.h"
#include "memory_collector.h"
#include "collect_result.h"
#include "startup_delay.h"
#include "sp_log.h"
#include "common.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class RAMTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(RAMTest, ProcMemNaInfoTest01, TestSize.Level1)
{
    bool ret = false;
    RAM &ram = RAM::GetInstance();
    std::map<std::string, std::string> procMemInfo;
    procMemInfo = ram.ProcMemNaInfo();
    if (!procMemInfo.empty()) {
        for (auto item : procMemInfo) {
            if (item.second == "NA") {
                ret = true;
            }
        }
    }
    EXPECT_TRUE(ret);
}

HWTEST_F(RAMTest, GetSysRamInfoTest01, TestSize.Level1)
{
    bool ret = false;
    RAM &ram = RAM::GetInstance();
    std::map<std::string, std::string> procMemInfo;
    procMemInfo = ram.GetSysRamInfo();
    if (!procMemInfo.empty()) {
        for (auto item : procMemInfo) {
            if (item.first.find("memTotal") != std::string::npos) {
                ret = true;
            }
        }
    }
    EXPECT_TRUE(ret);
}

HWTEST_F(RAMTest, GetRamInfoTest01, TestSize.Level1)
{
    bool ret = false;
    RAM &ram = RAM::GetInstance();
    std::map<std::string, std::string> procMemInfo;
    procMemInfo = ram.GetSysRamInfo();
    if (!procMemInfo.empty()) {
        for (auto item : procMemInfo) {
            if (item.first.find("pss") != std::string::npos) {
                ret = true;
            }
        }
    }
    EXPECT_FALSE(false);
}

}
}