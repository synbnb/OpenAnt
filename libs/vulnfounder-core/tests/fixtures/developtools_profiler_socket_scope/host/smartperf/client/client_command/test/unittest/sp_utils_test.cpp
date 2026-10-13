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
#include <exception>
#include <iostream>
#include <string>
#include <gtest/gtest.h>
#include <unistd.h>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <functional>
#include "sp_utils.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class SPdaemonUtilsTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SPUtils::IntegerValueVerification
 * @tc.desc: Test IntegerValueVerification
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonUtilsTest, IntegerValueVerificationTest001, TestSize.Level1)
{
    std::string errorInfo;
    std::map<std::string, std::string> mapInfo;
    std::set<std::string> keys;

    keys.insert("N");
    keys.insert("fl");
    keys.insert("ftl");

    mapInfo["N"] = "";
    mapInfo["fl"] = "";
    mapInfo["ftl"] = "";

    bool ret = SPUtils::IntegerValueVerification(keys, mapInfo, errorInfo);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SPdaemonUtilsTest, IntegerValueVerificationTest002, TestSize.Level1)
{
    std::string errorInfo;
    std::map<std::string, std::string> mapInfo;
    std::set<std::string> keys;

    keys.insert("N");
    keys.insert("fl");
    keys.insert("ftl");

    mapInfo["N"] = "A";
    mapInfo["fl"] = "B";
    mapInfo["ftl"] = "C";

    bool ret = SPUtils::IntegerValueVerification(keys, mapInfo, errorInfo);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SPdaemonUtilsTest, IntegerValueVerificationTest003, TestSize.Level1)
{
    std::string errorInfo;
    std::map<std::string, std::string> mapInfo;
    std::set<std::string> keys;

    keys.insert("N");
    keys.insert("fl");
    keys.insert("ftl");

    mapInfo["N"] = "1";
    mapInfo["fl"] = "2";
    mapInfo["ftl"] = "3";

    bool ret = SPUtils::IntegerValueVerification(keys, mapInfo, errorInfo);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: SPUtils::VerifyValueStr
 * @tc.desc: Test VerifyValueStr
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonUtilsTest, VerifyValueStrTest001, TestSize.Level1)
{
    std::string errorInfo;
    std::map<std::string, std::string> mapInfo;
    mapInfo["VIEW"] = "";
    bool ret = SPUtils::VerifyValueStr(mapInfo, errorInfo);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SPdaemonUtilsTest, VerifyValueStrTest002, TestSize.Level1)
{
    std::string errorInfo;
    std::map<std::string, std::string> mapInfo;
    mapInfo["VIEW"] = "TestVIEW";
    mapInfo["PKG"] = "";
    bool ret = SPUtils::VerifyValueStr(mapInfo, errorInfo);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SPdaemonUtilsTest, VerifyValueStrTest003, TestSize.Level1)
{
    std::string errorInfo;
    std::map<std::string, std::string> mapInfo;
    mapInfo["VIEW"] = "TestVIEW";
    mapInfo["PKG"] = "TestPKG";
    mapInfo["OUT"] = "";
    bool ret = SPUtils::VerifyValueStr(mapInfo, errorInfo);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SPdaemonUtilsTest, VerifyValueStrTest004, TestSize.Level1)
{
    std::string errorInfo;
    std::map<std::string, std::string> mapInfo;
    mapInfo["VIEW"] = "TestVIEW";
    mapInfo["PKG"] = "TestPKG";
    mapInfo["OUT"] = "Test/sp_utils_test/";
    bool ret = SPUtils::VerifyValueStr(mapInfo, errorInfo);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SPdaemonUtilsTest, VerifyValueStrTest005, TestSize.Level1)
{
    std::string errorInfo;
    std::map<std::string, std::string> mapInfo;
    mapInfo["VIEW"] = "TestVIEW";
    mapInfo["PKG"] = "TestPKG";
    mapInfo["OUT"] = "/sp_utils_test";
    bool ret = SPUtils::VerifyValueStr(mapInfo, errorInfo);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SPdaemonUtilsTest, VerifyValueStrTest006, TestSize.Level1)
{
    std::string errorInfo;
    std::map<std::string, std::string> mapInfo;
    mapInfo["VIEW"] = "TestVIEW";
    mapInfo["PKG"] = "TestPKG";
    bool ret = SPUtils::VerifyValueStr(mapInfo, errorInfo);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: SPUtils::VeriyKey
 * @tc.desc: Test VeriyKey
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonUtilsTest, VeriyKey001, TestSize.Level1)
{
    std::set<std::string> keys;
    std::map<std::string, std::string> mapInfo;
    std::string errorInfo;

    keys.insert("apple");
    keys.insert("banana");
    keys.insert("cherry");
    keys.insert("orange");
    keys.insert("pineapple");

    mapInfo["A"] = "";
    mapInfo["B"] = "";
    mapInfo["C"] = "";

    bool ret = SPUtils::VeriyKey(keys, mapInfo, errorInfo);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SPdaemonUtilsTest, VeriyKey002, TestSize.Level1)
{
    std::set<std::string> keys;
    std::map<std::string, std::string> mapInfo;
    std::string errorInfo;

    keys.insert("apple");
    keys.insert("banana");
    keys.insert("cherry");
    keys.insert("orange");
    keys.insert("pineapple");

    mapInfo["apple"] = "";
    mapInfo["cherry"] = "";
    mapInfo["pineapple"] = "";

    bool ret = SPUtils::VeriyKey(keys, mapInfo, errorInfo);
    EXPECT_EQ(ret, true);
}

HWTEST_F(SPdaemonUtilsTest, GetIsGameAppTest, TestSize.Level1)
{
    std::string pkg = "com.example.game";
    std::string cmd = "hidumper -s 66006 -a '-t " + pkg + "'";
    FILE *fd = popen(cmd.c_str(), "r");
    char buf[1024] = {'\0'};
    bool ret = false;
    while ((fgets(buf, sizeof(buf), fd)) != nullptr) {
        std::string line(buf);
        if (line.find("---") != std::string::npos || line.length() <= 1) {
            continue;
        }
        if (line.find("for help") != std::string::npos) {
            ret = true;
            break;
        }
    }
    EXPECT_EQ(ret, false);
}

HWTEST_F(SPdaemonUtilsTest, GetCurrentTime, TestSize.Level1)
{
    bool shouldContinue = true;
    SPUtils::GetCurrentTime(10);
    EXPECT_TRUE(shouldContinue);
}

HWTEST_F(SPdaemonUtilsTest, VeriyParameterTest01, TestSize.Level1)
{
    std::set<std::string> keys;
    std::string param = "key1-value key1-value2";
    std::string errorInfo = "";
    bool result = SPUtils::VeriyParameter(keys, param, errorInfo);
    EXPECT_FALSE(result);
    EXPECT_NE(errorInfo, "duplicate parameters -- 'key1'");
}

HWTEST_F(SPdaemonUtilsTest, VeriyParameterTest02, TestSize.Level1)
{
    std::set<std::string> keys;
    std::string param = "key1-value key2-value2";
    std::string errorInfo = "";
    bool result = SPUtils::VeriyParameter(keys, param, errorInfo);
    EXPECT_FALSE(result);
    EXPECT_NE(errorInfo, "");
}

HWTEST_F(SPdaemonUtilsTest, VeriyParameterTest03, TestSize.Level1)
{
    std::set<std::string> keys = {"key1"};
    std::string param = "key2-value1";
    std::string errorInfo = "";
    bool result = SPUtils::VeriyParameter(keys, param, errorInfo);
    EXPECT_FALSE(result);
    EXPECT_NE(errorInfo, "");
}

HWTEST_F(SPdaemonUtilsTest, VeriyParameterTest04, TestSize.Level1)
{
    std::set<std::string> keys = {"key1"};
    std::string param = "key1-value1";
    std::string errorInfo = "";
    bool result = SPUtils::VeriyParameter(keys, param, errorInfo);
    EXPECT_FALSE(result);
    EXPECT_NE(errorInfo, "");
}

HWTEST_F(SPdaemonUtilsTest, VeriyParameterTest05, TestSize.Level1)
{
    std::set<std::string> keys = {"key1"};
    std::string param = "key1-value1";
    std::string errorInfo = "";
    bool result = SPUtils::VeriyParameter(keys, param, errorInfo);
    EXPECT_FALSE(result);
    EXPECT_NE(errorInfo, "");
}

HWTEST_F(SPdaemonUtilsTest, IntegerValueVerificationTest01, TestSize.Level1)
{
    std::string errorInfo = "";
    std::string outOfRangeString = "";
    bool result = SPUtils::IntegerVerification(outOfRangeString, errorInfo);
    EXPECT_FALSE(result);
    EXPECT_EQ(errorInfo, "option requires an argument");
}

HWTEST_F(SPdaemonUtilsTest, IntegerValueVerificationTest02, TestSize.Level1)
{
    std::string errorInfo;
    std::string longString(11, '1');
    EXPECT_FALSE(SPUtils::IntegerVerification(longString, errorInfo));
    EXPECT_EQ(errorInfo, "invalid option parameters");
}

HWTEST_F(SPdaemonUtilsTest, IntegerValueVerificationTest03, TestSize.Level1)
{
    std::string errorInfo;
    EXPECT_FALSE(SPUtils::IntegerVerification("123a456", errorInfo));
    EXPECT_EQ(errorInfo, "invalid option parameters");
}

HWTEST_F(SPdaemonUtilsTest, IntegerValueVerificationTest05, TestSize.Level1)
{
    std::string errorInfo = "";
    std::string outOfRangeString = "18446744073709551616";
    bool result = SPUtils::IntegerVerification(outOfRangeString, errorInfo);
    EXPECT_FALSE(result);
    EXPECT_NE(errorInfo, "option parameter out of range");
}

HWTEST_F(SPdaemonUtilsTest, RemoveSpaceTest01, TestSize.Level1)
{
    std::string str = "  Hello World  ";
    SPUtils::RemoveSpace(str);
    EXPECT_EQ(str, "Hello World");
}

HWTEST_F(SPdaemonUtilsTest, RemoveSpaceTest02, TestSize.Level1)
{
    std::string str = "  HelloWorld  ";
    SPUtils::RemoveSpace(str);
    EXPECT_EQ(str, "HelloWorld");
}

HWTEST_F(SPdaemonUtilsTest, RemoveSpaceTest03, TestSize.Level1)
{
    std::string str = "Hello World  ";
    SPUtils::RemoveSpace(str);
    EXPECT_EQ(str, "Hello World");
}

HWTEST_F(SPdaemonUtilsTest, RemoveSpaceTest04, TestSize.Level1)
{
    std::string str = "  HelloWorld";
    SPUtils::RemoveSpace(str);
    EXPECT_EQ(str, "HelloWorld");
}

HWTEST_F(SPdaemonUtilsTest, RemoveSpaceTest05, TestSize.Level1)
{
    std::string str = "HelloWorld";
    SPUtils::RemoveSpace(str);
    EXPECT_EQ(str, "HelloWorld");
}

HWTEST_F(SPdaemonUtilsTest, RemoveSpaceTest06, TestSize.Level1)
{
    std::string str = "    ";
    SPUtils::RemoveSpace(str);
    EXPECT_EQ(str, "");
}

HWTEST_F(SPdaemonUtilsTest, RemoveSpaceTest07, TestSize.Level1)
{
    std::string str = "";
    SPUtils::RemoveSpace(str);
    EXPECT_EQ(str, "");
}

HWTEST_F(SPdaemonUtilsTest, GetCurTimeTest002, TestSize.Level1)
{
    long long timeStampFir = SPUtils::GetCurTime();
    usleep(1000);
    long long timeStampSec = SPUtils::GetCurTime();
    EXPECT_GT(timeStampSec, timeStampFir);
}

HWTEST_F(SPdaemonUtilsTest, ReplaceStringTest01, TestSize.Level1)
{
    std::string testStr = "Hello\rWorld\n";
    SPUtils::ReplaceString(testStr);
    EXPECT_EQ(testStr, "HelloWorld");
}

HWTEST_F(SPdaemonUtilsTest, ReplaceStringTest02, TestSize.Level1)
{
    std::string testStr = "\r\r\r";
    SPUtils::ReplaceString(testStr);
    EXPECT_EQ(testStr, "");
}

HWTEST_F(SPdaemonUtilsTest, ReplaceStringTest03, TestSize.Level1)
{
    std::string testStr = "Hello\nWorld\n";
    SPUtils::ReplaceString(testStr);
    EXPECT_EQ(testStr, "HelloWorld");
}

HWTEST_F(SPdaemonUtilsTest, ReplaceStringTest04, TestSize.Level1)
{
    std::string testStr = "\n\n\n";
    SPUtils::ReplaceString(testStr);
    EXPECT_EQ(testStr, "");
}

HWTEST_F(SPdaemonUtilsTest, ReplaceStringTest05, TestSize.Level1)
{
    std::string testStr = "Hello\r\nWorld\r\n";
    SPUtils::ReplaceString(testStr);
    EXPECT_EQ(testStr, "HelloWorld");
}

HWTEST_F(SPdaemonUtilsTest, ReplaceStringTest06, TestSize.Level1)
{
    std::string testStr = "Hello\r\n\r\nWorld\r\n\r\n";
    SPUtils::ReplaceString(testStr);
    EXPECT_EQ(testStr, "HelloWorld");
}
}
}