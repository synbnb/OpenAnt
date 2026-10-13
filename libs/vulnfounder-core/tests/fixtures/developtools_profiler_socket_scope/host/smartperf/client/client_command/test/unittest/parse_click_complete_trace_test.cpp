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
#include <thread>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdio>
#include <sstream>
#include <iomanip>
#include "parse_click_complete_trace.h"
#include "sp_utils.h"
#include "sp_log.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class ParseClickCompleteTraceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(ParseClickCompleteTraceTest, ParseCompleteTrace_ShouldReturnZerzo_WhenFileOpenFails, TestSize.Level1)
{
    std::string fileNamePath = "invalid_file_path";
    ParseClickCompleteTrace parseClickCompleteTrace;
    double result = parseClickCompleteTrace.ParseCompleteTrace(fileNamePath);
    ASSERT_EQ(result, 0);
}

HWTEST_F(ParseClickCompleteTraceTest, getTime_ShouldReturnCorrentTime_WhenEndTimeIsvalid, TestSize.Level1)
{
    ParseClickCompleteTrace parseClickCompleteTrace;
    std::string endTime = "123.456";
    double result = parseClickCompleteTrace.GetTime(endTime);
    ASSERT_EQ(result, -1);
}

HWTEST_F(ParseClickCompleteTraceTest, Getpid_WhenAppPidnumIsZeroTest01, TestSize.Level1)
{
    ParseClickCompleteTrace parseClickCompleteTrace;
    std::string line = "task_newtask: pid=1234 comm=appspawn";
    std::string pn = "test";
    std::string pb = "1234";
    EXPECT_EQ(parseClickCompleteTrace.GetPid(line, pn, pb), "1234");
}

HWTEST_F(ParseClickCompleteTraceTest, Getpid_WhenAppPidnumIsZeroTest02, TestSize.Level1)
{
    ParseClickCompleteTrace parseClickCompleteTrace;
    std::string line = "task_newtask: pid=1234 prio=10";
    std::string pn = "test1234";
    std::string pb = "1234";
    EXPECT_EQ(parseClickCompleteTrace.GetPid(line, pn, pb), "1234");
}

HWTEST_F(ParseClickCompleteTraceTest, Getpid_WhenAppPidnumNotZeroTest01, TestSize.Level1)
{
    ParseClickCompleteTrace parseClickCompleteTrace;
    std::string line = "task_newtask: pid=1234 prio=10";
    std::string pn = "test1234";
    std::string pb = "1234";
    EXPECT_EQ(parseClickCompleteTrace.GetPid(line, pn, pb), pb);
}

}
}