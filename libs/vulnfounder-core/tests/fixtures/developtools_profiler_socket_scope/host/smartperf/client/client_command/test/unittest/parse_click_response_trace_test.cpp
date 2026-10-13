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
#include "parse_click_response_trace.h"
#include "sp_utils.h"
#include "sp_log.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class ParseClickResponseTraceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() {}
    void TearDown() {}
};
/**
 * @tc.name: ParseClickResponseTraceTest_ParseResponseTrace_001
 * @tc.desc: 验证 ParseResponseTrace 当文件打开失败时
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_ParseResponseTrace_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_ParseResponseTrace_001";
    std::string fileNamePath = "invalid_file_path";
    ParseClickResponseTrace parseClickResponseTrace;
    double result = parseClickResponseTrace.ParseResponseTrace(fileNamePath);
    ASSERT_EQ(result, 0);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_ParseResponseTrace_001";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetTime_001
 * @tc.desc: 验证 GetTime 当 endTime 为 "0" 时
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetTime_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetTime_001";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string startTime = "123.456";
    std::string endTime = "0";
    double result = parseClickResponseTrace.GetTime(startTime, endTime);
    EXPECT_EQ(result, -1);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetTime_001";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetTime_002
 * @tc.desc: 验证 GetTime 当 startTime 为 "0" 时
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetTime_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetTime_002";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string startTime = "0";
    std::string endTime = "123.456";
    double result = parseClickResponseTrace.GetTime(startTime, endTime);
    EXPECT_EQ(result, -1);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetTime_002";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetTime_003
 * @tc.desc: 验证 GetTime 当 startTime 和 endTime 都为 "0" 时
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetTime_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetTime_003";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string startTime = "0";
    std::string endTime = "0";
    double result = parseClickResponseTrace.GetTime(startTime, endTime);
    EXPECT_EQ(result, -1);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetTime_003";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetTime_004
 * @tc.desc: 验证 GetTime 正常情况
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetTime_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetTime_004";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string startTime = "123.456";
    std::string endTime = "123.456";
    double result = parseClickResponseTrace.GetTime(startTime, endTime);
    EXPECT_EQ(result, -1);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetTime_004";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetTime_005
 * @tc.desc: 验证 GetTime 空字符串
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetTime_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetTime_005";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string startTime = "";
    std::string endTime = "";
    double result = parseClickResponseTrace.GetTime(startTime, endTime);
    EXPECT_EQ(result, -1);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetTime_005";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetTime_006
 * @tc.desc: 验证 GetTime 无小数点的时间
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetTime_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetTime_006";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string startTime = "123456";
    std::string endTime = "123456";
    double result = parseClickResponseTrace.GetTime(startTime, endTime);
    EXPECT_EQ(result, -1);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetTime_006";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetTime_007
 * @tc.desc: 验证 GetTime 边界值测试
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetTime_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetTime_007";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string startTime = "999.999";
    std::string endTime = "999.999";
    double result = parseClickResponseTrace.GetTime(startTime, endTime);
    EXPECT_EQ(result, -1);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetTime_007";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetPid_001
 * @tc.desc: 验证 GetPid 当 appPidnum==0, pn.length()<5, 找到 task_newtask 和 comm=appspawn
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetPid_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetPid_001";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "task_newtask: pid=5678 comm=appspawn";
    std::string pn = "test";
    std::string pb = "5678";
    std::string result = parseClickResponseTrace.GetPid(line, pn, pb);
    EXPECT_EQ(result, "5678");
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetPid_001";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetPid_002
 * @tc.desc: 验证 GetPid 当 appPidnum==0, pn.length()<5, 未找到 comm=appspawn
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetPid_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetPid_002";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "task_newtask: pid=5678 comm=other";
    std::string pn = "test";
    std::string pb = "5678";
    std::string result = parseClickResponseTrace.GetPid(line, pn, pb);
    EXPECT_EQ(result, pb);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetPid_002";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetPid_003
 * @tc.desc: 验证 GetPid 当 appPidnum==0, pn.length()<5, 未找到 task_newtask
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetPid_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetPid_003";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "some other line";
    std::string pn = "test";
    std::string pb = "1234";
    std::string result = parseClickResponseTrace.GetPid(line, pn, pb);
    EXPECT_EQ(result, pb);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetPid_003";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetPid_004
 * @tc.desc: 验证 GetPid 当 appPidnum==0, pn.length()>=5, 找到 pn
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetPid_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetPid_004";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "com.example.test pid=9999 prio=10";
    std::string pn = "com.example.test";
    std::string pb = "9999";
    std::string result = parseClickResponseTrace.GetPid(line, pn, pb);
    EXPECT_EQ(result, "9999");
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetPid_004";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetPid_005
 * @tc.desc: 验证 GetPid 当 appPidnum==0, pn.length()>=5, 未找到 pn
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetPid_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetPid_005";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "some other package pid=9999 prio=10";
    std::string pn = "com.example.test";
    std::string pb = "9999";
    std::string result = parseClickResponseTrace.GetPid(line, pn, pb);
    EXPECT_EQ(result, pb);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetPid_005";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetPid_006
 * @tc.desc: 验证 GetPid 当 appPidnum!=0 时
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetPid_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetPid_006";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "task_newtask: pid=1234 comm=appspawn";
    std::string pn = "test";
    std::string pb = "1234";

    parseClickResponseTrace.GetPid(line, pn, pb);

    std::string line2 = "another line";
    std::string result = parseClickResponseTrace.GetPid(line2, pn, pb);
    EXPECT_TRUE(result.empty());
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetPid_006";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetPid_007
 * @tc.desc: 验证 GetPid 空行
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetPid_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetPid_007";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "";
    std::string pn = "test";
    std::string pb = "1234";
    std::string result = parseClickResponseTrace.GetPid(line, pn, pb);
    EXPECT_EQ(result, pb);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetPid_007";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetPid_008
 * @tc.desc: 验证 GetPid pn 为空
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetPid_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetPid_008";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "task_newtask: pid=1234 comm=appspawn";
    std::string pn = "";
    std::string pb = "1234";
    std::string result = parseClickResponseTrace.GetPid(line, pn, pb);
    EXPECT_EQ(result, "1234");
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetPid_008";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetPid_009
 * @tc.desc: 验证 GetPid pb 为空
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetPid_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetPid_009";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "some line";
    std::string pn = "test";
    std::string pb = "";
    std::string result = parseClickResponseTrace.GetPid(line, pn, pb);
    EXPECT_EQ(result, pb);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetPid_009";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetPid_010
 * @tc.desc: 验证 GetPid 包含特殊字符的包名
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetPid_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetPid_010";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "com.example.test_v2 pid=8888 prio=10";
    std::string pn = "com.example.test_v2";
    std::string pb = "8888";
    std::string result = parseClickResponseTrace.GetPid(line, pn, pb);
    EXPECT_EQ(result, "8888");
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetPid_010";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetPid_011
 * @tc.desc: 验证 GetPid PID 为 0
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetPid_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetPid_011";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "task_newtask: pid=0 comm=appspawn";
    std::string pn = "test";
    std::string pb = "0";
    std::string result = parseClickResponseTrace.GetPid(line, pn, pb);
    EXPECT_EQ(result, "0");
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetPid_011";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetPid_012
 * @tc.desc: 验证 GetPid PID 为最大值
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetPid_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetPid_012";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "task_newtask: pid=2147483647 comm=appspawn";
    std::string pn = "test";
    std::string pb = "2147483647";
    std::string result = parseClickResponseTrace.GetPid(line, pn, pb);
    EXPECT_EQ(result, "2147483647");
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetPid_012";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetPid_013
 * @tc.desc: 验证 GetPid 长包名
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetPid_013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetPid_013";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "com.very.long.package.name.with.many.dots pid=7777 prio=10";
    std::string pn = "com.very.long.package.name.with.many.dots";
    std::string pb = "7777";
    std::string result = parseClickResponseTrace.GetPid(line, pn, pb);
    EXPECT_EQ(result, "7777");
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetPid_013";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetPid_014
 * @tc.desc: 验证 GetPid 包含多个空格
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetPid_014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetPid_014";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "task_newtask:  pid=1234  comm=appspawn";
    std::string pn = "test";
    std::string pb = "1234";
    std::string result = parseClickResponseTrace.GetPid(line, pn, pb);
    EXPECT_EQ(result, "1234");
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetPid_014";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetPid_015
 * @tc.desc: 验证 GetPid 验证 appPidnum 累加
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetPid_015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetPid_015";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "task_newtask: pid=1234 comm=appspawn";
    std::string pn = "test";
    std::string pb = "1234";

    parseClickResponseTrace.GetPid(line, pn, pb);

    std::string line2 = "com.example.test pid=5678 prio=10";
    std::string pn2 = "com.example.test";
    std::string pb2 = "5678";
    std::string result = parseClickResponseTrace.GetPid(line2, pn2, pb2);
    EXPECT_TRUE(result.empty());

    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetPid_015";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetStartTime_001
 * @tc.desc: 验证 GetStartTime 找到 H:touchEventDispatch 且 flagTouch<=3
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetStartTime_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetStartTime_001";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "....123.456: H:touchEventDispatch";
    std::string startTimeBefore = "0";
    std::string result = parseClickResponseTrace.GetStartTime(line, startTimeBefore);
    EXPECT_FALSE(result.empty());
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetStartTime_001";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetStartTime_002
 * @tc.desc: 验证 GetStartTime 找到 H:TouchEventDispatch
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetStartTime_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetStartTime_002";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "....123.456: H:TouchEventDispatch";
    std::string startTimeBefore = "0";
    std::string result = parseClickResponseTrace.GetStartTime(line, startTimeBefore);
    EXPECT_FALSE(result.empty());
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetStartTime_002";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetStartTime_003
 * @tc.desc: 验证 GetStartTime 找到 H:PointerEventDispatch
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetStartTime_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetStartTime_003";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "....123.456: H:PointerEventDispatch";
    std::string startTimeBefore = "0";
    std::string result = parseClickResponseTrace.GetStartTime(line, startTimeBefore);
    EXPECT_FALSE(result.empty());
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetStartTime_003";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetStartTime_004
 * @tc.desc: 验证 GetStartTime 找到 H:KeyEventDispatch
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetStartTime_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetStartTime_004";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "....123.456: H:KeyEventDispatch";
    std::string startTimeBefore = "0";
    std::string result = parseClickResponseTrace.GetStartTime(line, startTimeBefore);
    EXPECT_FALSE(result.empty());
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetStartTime_004";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetStartTime_005
 * @tc.desc: 验证 GetStartTime 未找到任何事件
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetStartTime_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetStartTime_005";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "....123.456: H:SomeOtherEvent";
    std::string startTimeBefore = "0";
    std::string result = parseClickResponseTrace.GetStartTime(line, startTimeBefore);
    EXPECT_EQ(result, startTimeBefore);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetStartTime_005";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetStartTime_006
 * @tc.desc: 验证 GetStartTime 当 flagTouch>3 时
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetStartTime_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetStartTime_006";
    ParseClickResponseTrace parseClickResponseTrace;

    for (int i = 0; i < 4; i++) {
        std::string line = "....123.456: H:touchEventDispatch";
        parseClickResponseTrace.GetStartTime(line, "0");
    }

    std::string line = "....123.456: H:touchEventDispatch";
    std::string startTimeBefore = "0";
    std::string result = parseClickResponseTrace.GetStartTime(line, startTimeBefore);
    EXPECT_EQ(result, startTimeBefore);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetStartTime_006";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetStartTime_007
 * @tc.desc: 验证 GetStartTime 多次调用
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetStartTime_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetStartTime_007";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "....123.456: H:touchEventDispatch";
    std::string startTimeBefore = "0";

    for (int i = 0; i < 3; i++) {
        std::string result = parseClickResponseTrace.GetStartTime(line, startTimeBefore);
        EXPECT_FALSE(result.empty());
    }

    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetStartTime_007";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetStartTime_008
 * @tc.desc: 验证 GetStartTime 空行
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetStartTime_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetStartTime_008";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "";
    std::string startTimeBefore = "0";
    std::string result = parseClickResponseTrace.GetStartTime(line, startTimeBefore);
    EXPECT_EQ(result, startTimeBefore);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetStartTime_008";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetStartTime_009
 * @tc.desc: 验证 GetStartTime 特殊字符行
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetStartTime_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetStartTime_009";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "....123.456: H:touchEventDispatch (special@#$%characters)";
    std::string startTimeBefore = "0";
    std::string result = parseClickResponseTrace.GetStartTime(line, startTimeBefore);
    EXPECT_FALSE(result.empty());
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetStartTime_009";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetStartTime_010
 * @tc.desc: 验证 GetStartTime 没有 "...." 的时间戳格式
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetStartTime_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetStartTime_010";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "H:touchEventDispatch";
    std::string startTimeBefore = "0";
    std::string result = parseClickResponseTrace.GetStartTime(line, startTimeBefore);
    EXPECT_FALSE(result.empty());
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetStartTime_010";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetStartTime_011
 * @tc.desc: 验证 GetStartTime 多个事件在同一行
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetStartTime_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetStartTime_011";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "....123.456: H:touchEventDispatch H:TouchEventDispatch";
    std::string startTimeBefore = "0";
    std::string result = parseClickResponseTrace.GetStartTime(line, startTimeBefore);
    EXPECT_FALSE(result.empty());
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetStartTime_011";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetStartTime_012
 * @tc.desc: 验证 GetStartTime 边界值时间戳
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetStartTime_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetStartTime_012";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "....0.000: H:touchEventDispatch";
    std::string startTimeBefore = "0";
    std::string result = parseClickResponseTrace.GetStartTime(line, startTimeBefore);
    EXPECT_FALSE(result.empty());
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetStartTime_012";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetStartTime_013
 * @tc.desc: 验证 GetStartTime 大时间戳
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetStartTime_013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetStartTime_013";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "....999999.999: H:touchEventDispatch";
    std::string startTimeBefore = "0";
    std::string result = parseClickResponseTrace.GetStartTime(line, startTimeBefore);
    EXPECT_FALSE(result.empty());
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetStartTime_013";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetStartTime_014
 * @tc.desc: 验证 GetStartTime 验证返回值非空
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetStartTime_014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetStartTime_014";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "....123.456: H:touchEventDispatch";
    std::string startTimeBefore = "100.100";
    std::string result = parseClickResponseTrace.GetStartTime(line, startTimeBefore);
    EXPECT_FALSE(result.empty());
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetStartTime_014";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetStartTime_015
 * @tc.desc: 验证 GetStartTime 返回 previous 值的情况
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetStartTime_015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetStartTime_015";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "some random line without event";
    std::string startTimeBefore = "100.100";
    std::string result = parseClickResponseTrace.GetStartTime(line, startTimeBefore);
    EXPECT_EQ(result, startTimeBefore);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetStartTime_015";
}

/**
 * @tc.name: ParseClickResponseTraceTest_MultipleCalls_001
 * @tc.desc: 验证多次调用 GetPid 的行为
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_MultipleCalls_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_MultipleCalls_001";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "task_newtask: pid=1234 comm=appspawn";
    std::string pn = "test";
    std::string pb = "1234";

    for (int i = 0; i < 5; i++) {
        std::string result = parseClickResponseTrace.GetPid(line, pn, pb);
        if (i == 0) {
            EXPECT_FALSE(result.empty());
        } else {
            EXPECT_TRUE(result.empty());
        }
    }

    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_MultipleCalls_001";
}

/**
 * @tc.name: ParseClickResponseTraceTest_MultipleCalls_002
 * @tc.desc: 验证多次调用 GetStartTime 的行为
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_MultipleCalls_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_MultipleCalls_002";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "....123.456: H:touchEventDispatch";
    std::string startTimeBefore = "0";

    for (int i = 0; i < 5; i++) {
        std::string result = parseClickResponseTrace.GetStartTime(line, startTimeBefore);
        EXPECT_FALSE(result.empty());
    }

    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_MultipleCalls_002";
}

/**
 * @tc.name: ParseClickResponseTraceTest_MultipleCalls_003
 * @tc.desc: 验证多次调用 GetTime 的行为
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_MultipleCalls_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_MultipleCalls_003";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string startTime = "123.456";
    std::string endTime = "123.456";

    for (int i = 0; i < 5; i++) {
        double result = parseClickResponseTrace.GetTime(startTime, endTime);
        EXPECT_EQ(result, -1);
    }

    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_MultipleCalls_003";
}

/**
 * @tc.name: ParseClickResponseTraceTest_EdgeCases_001
 * @tc.desc: 验证边界情况和特殊输入
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_EdgeCases_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_EdgeCases_001";
    ParseClickResponseTrace parseClickResponseTrace;

    std::vector<std::pair<std::string, std::string>> testCases = {
        {"....000.000: H:touchEventDispatch", "0"},
        {"....999.999: H:TouchEventDispatch", "0"},
        {"....1.001: H:PointerEventDispatch", "0"},
        {"....1000.000: H:KeyEventDispatch", "0"}
    };

    for (const auto& testCase : testCases) {
        std::string result = parseClickResponseTrace.GetStartTime(testCase.first, testCase.second);
        EXPECT_FALSE(result.empty());
    }

    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_EdgeCases_001";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetTime_008
 * @tc.desc: 验证 GetTime 参数顺序交换
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetTime_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetTime_008";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string startTime = "124.456";
    std::string endTime = "123.456";
    double result = parseClickResponseTrace.GetTime(startTime, endTime);
    EXPECT_EQ(result, -1);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetTime_008";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetTime_009
 * @tc.desc: 验证 GetTime 时间差较大
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetTime_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetTime_009";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string startTime = "100.000";
    std::string endTime = "200.000";
    double result = parseClickResponseTrace.GetTime(startTime, endTime);
    EXPECT_EQ(result, -1);
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetTime_009";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetStartTime_016
 * @tc.desc: 验证 GetStartTime 与不同 previous 值的组合
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetStartTime_016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetStartTime_016";
    ParseClickResponseTrace parseClickResponseTrace;
    std::string line = "....123.456: H:touchEventDispatch";

    std::vector<std::string> previousValues = {"0", "50.000", "100.500", "150.250"};

    for (const auto& prev : previousValues) {
        std::string result = parseClickResponseTrace.GetStartTime(line, prev);
        EXPECT_FALSE(result.empty());
    }

    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetStartTime_016";
}

/**
 * @tc.name: ParseClickResponseTraceTest_GetPid_016
 * @tc.desc: 验证 GetPid 连续调用时的行为
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_GetPid_016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_GetPid_016";
    ParseClickResponseTrace parseClickResponseTrace;

    std::vector<std::tuple<std::string, std::string, std::string>> testCases = {
        {"task_newtask: pid=1001 comm=appspawn", "test", "1001"},
        {"task_newtask: pid=1002 comm=appspawn", "test", "1002"},
        {"task_newtask: pid=1003 comm=appspawn", "test", "1003"}
    };

    int callCount = 0;
    for (const auto& testCase : testCases) {
        std::string line = std::get<0>(testCase);
        std::string pn = std::get<1>(testCase);
        std::string pb = std::get<2>(testCase);
        std::string result = parseClickResponseTrace.GetPid(line, pn, pb);

        if (callCount == 0) {
            EXPECT_EQ(result, "1001");
        } else {
            EXPECT_TRUE(result.empty());
        }
        callCount++;
    }

    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_GetPid_016";
}

/**
 * @tc.name: ParseClickResponseTraceTest_Comprehensive_001
 * @tc.desc: 综合测试：验证多个方法的组合使用
 * @tc.type: FUNC
 */
HWTEST_F(ParseClickResponseTraceTest, ParseClickResponseTraceTest_Comprehensive_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-begin ParseClickResponseTraceTest_Comprehensive_001";
    ParseClickResponseTrace parseClickResponseTrace;

    std::string line1 = "task_newtask: pid=1234 comm=appspawn";
    std::string pn = "test";
    std::string pb = "1234";
    std::string pidResult = parseClickResponseTrace.GetPid(line1, pn, pb);
    EXPECT_EQ(pidResult, "1234");

    std::string line2 = "....123.456: H:touchEventDispatch";
    std::string startTimeBefore = "0";
    std::string startTimeResult = parseClickResponseTrace.GetStartTime(line2, startTimeBefore);
    EXPECT_FALSE(startTimeResult.empty());

    std::string startTime = "123.456";
    std::string endTime = "123.456";
    double timeResult = parseClickResponseTrace.GetTime(startTime, endTime);
    EXPECT_EQ(timeResult, -1);

    GTEST_LOG_(INFO) << "ParseClickResponseTraceTest-end ParseClickResponseTraceTest_Comprehensive_001";
}
}
}
