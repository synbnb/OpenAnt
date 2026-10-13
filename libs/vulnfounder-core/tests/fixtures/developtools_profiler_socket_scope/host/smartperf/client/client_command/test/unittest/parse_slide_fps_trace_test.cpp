/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
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
#include <fstream>
#include <string>
#include <iostream>
#include <regex>
#include "parse_slide_fps_trace.h"
#include "sp_log.h"
#include "sp_utils.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class ParseSlideFpsTraceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() {}
    void TearDown() {}

    bool needTime = false;
    int frameNum = 0;
    int frameNow = 0;
    int count = 0;
    int four = 4;
    double touchTime = 0;
    double responseTime = 0;
    double doCompositionTime = 0;
    double completionTime = 0.035;
    double completeTime = 0;
    int swiperScrollFlag = 0;
    int swiperFlingflag = 0;
    int listFlag = 0;
};

HWTEST_F(ParseSlideFpsTraceTest, ParseSlideFpsTraceNoh01, TestSize.Level1)
{
    ParseSlideFpsTrace parseSlideFpsTrace;
    std::string file = "non_existent_file.txt";
    double result = parseSlideFpsTrace.ParseSlideFpsTraceNoh(file);
    EXPECT_EQ(result, -1.0);
}

HWTEST_F(ParseSlideFpsTraceTest, ParseSlideCalculateTime01, TestSize.Level1)
{
    ParseSlideFpsTrace parseSlideFpsTrace;
    completeTime = 0;
    responseTime = 0;
    EXPECT_EQ(-1.0, parseSlideFpsTrace.CalculateTime());
}

HWTEST_F(ParseSlideFpsTraceTest, ParseSlideCalculateTime02, TestSize.Level1)
{
    ParseSlideFpsTrace parseSlideFpsTrace;
    completeTime = 10;
    responseTime = 5;
    EXPECT_EQ(-1.0, parseSlideFpsTrace.CalculateTime());
}

HWTEST_F(ParseSlideFpsTraceTest, ParseSlideCalculateTime03, TestSize.Level1)
{
    ParseSlideFpsTrace parseSlideFpsTrace;
    completeTime = 120.5;
    responseTime = 50;
    EXPECT_EQ(-1.0, parseSlideFpsTrace.CalculateTime());
}

HWTEST_F(ParseSlideFpsTraceTest, ParseSlideAppSwiperScroll01, TestSize.Level1)
{
    ParseSlideFpsTrace parseSlideFpsTrace;
    std::string line = "H:APP_SWIPER_SCROLL,123456789";
    parseSlideFpsTrace.AppSwiperScroll(line);
    ASSERT_EQ(touchTime, 0);
    ASSERT_EQ(swiperScrollFlag, 0);
}

HWTEST_F(ParseSlideFpsTraceTest, ParseSlideAppSwiperScroll02, TestSize.Level1)
{
    ParseSlideFpsTrace parseSlideFpsTrace;
    std::string line = "H:APP_SWIPER_FLING,987654321";
    swiperScrollFlag = 1;
    doCompositionTime = 100;
    parseSlideFpsTrace.AppSwiperScroll(line);
    ASSERT_EQ(completeTime, 0);
    ASSERT_EQ(swiperFlingflag, 0);
}

HWTEST_F(ParseSlideFpsTraceTest, ParseSlideAppSwiperScroll03, TestSize.Level1)
{
    ParseSlideFpsTrace parseSlideFpsTrace;
    std::string line = "H:APP_SWIPER_SCROLL,123456789";
    parseSlideFpsTrace.AppSwiperScroll(line);
    doCompositionTime = 123456790;
    parseSlideFpsTrace.AppSwiperScroll(line);
    ASSERT_EQ(responseTime, 0);
    ASSERT_EQ(frameNow, 0);
    ASSERT_EQ(needTime, false);
}

HWTEST_F(ParseSlideFpsTraceTest, ParseSlideGetLineTime01, TestSize.Level1)
{
    ParseSlideFpsTrace parseSlideFpsTrace;
    std::string lineStr = "....10:12:34:56";
    std::string expected = "12:34:56";
    EXPECT_EQ(parseSlideFpsTrace.GetLineTime(lineStr), expected);
}

HWTEST_F(ParseSlideFpsTraceTest, ParseSlideGetLineTime02, TestSize.Level1)
{
    ParseSlideFpsTrace parseSlideFpsTrace;
    std::string lineStr = ".......";
    std::string expected = "";
    EXPECT_EQ(parseSlideFpsTrace.GetLineTime(lineStr), expected);
}

HWTEST_F(ParseSlideFpsTraceTest, ParseSlideCutString01, TestSize.Level1)
{
    ParseSlideFpsTrace parseSlideFpsTrace;
    std::string lineStr = "startTestend";
    std::string start = "start";
    std::string end = "end";
    size_t offset = 0;
    std::string expected = "startTest";
    std::string result = parseSlideFpsTrace.CutString(lineStr, start, end, offset);
    EXPECT_EQ(expected, result);
}

HWTEST_F(ParseSlideFpsTraceTest, ParseSlideCutString02, TestSize.Level1)
{
    ParseSlideFpsTrace parseSlideFpsTrace;
    std::string lineStr = "startTestend";
    std::string start = "start";
    std::string end = "end";
    size_t offset = 9;
    std::string expected = "";
    std::string result = parseSlideFpsTrace.CutString(lineStr, start, end, offset);
    EXPECT_EQ(expected, result);
}

HWTEST_F(ParseSlideFpsTraceTest, ParseSlideCutString03, TestSize.Level1)
{
    ParseSlideFpsTrace parseSlideFpsTrace;
    std::string lineStr = "startTestend";
    std::string start = "start";
    std::string end = "end";
    size_t offset = 10;
    std::string expected = "nd";
    std::string result = parseSlideFpsTrace.CutString(lineStr, start, end, offset);
    EXPECT_EQ(expected, result);
}
}
}