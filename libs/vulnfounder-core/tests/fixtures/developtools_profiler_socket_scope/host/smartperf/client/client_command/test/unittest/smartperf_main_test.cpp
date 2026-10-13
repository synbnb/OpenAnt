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
#include <thread>
#include <gtest/gtest.h>
#include <unistd.h>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <functional>
#include "sp_utils.h"
#include "common.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class SPdaemonMainTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

std::string g_getOptions(std::vector<std::string> &argv)
{
    std::string str = "";
    std::string strFlag;
    bool isFill = false;
    for (std::size_t i = 0; i < argv.size(); i++) {
        if (!isFill) {
            strFlag = argv[i];
            if (std::string::npos != strFlag.find("SP_daemon")) {
                isFill = true;
            }
        } else {
            str += argv[i];
            if (i + 1 != argv.size()) {
                str += " ";
            }
        }
    }
    return str;
}

bool CheckCMDParam(std::vector<std::string> &argv, std::string &errorInfo)
{
    std::string str = g_getOptions(argv);
    std::set<std::string> keys;

    if (str.empty()) {
        return true;
    }

    if (std::string::npos != str.find("--help") || std::string::npos != str.find("--version")) {
        std::vector<std::string> out;
        OHOS::SmartPerf::SPUtils::StrSplit(str, "-", out);
        if (1 != out.size()) {
            errorInfo = "--help and --version cannot be used together with other options";
            return false;
        } else {
            return true;
        }
    }

    keys.insert("editor");
    keys.insert("profilerfps");
    keys.insert("start");
    keys.insert("stop");
    keys.insert("screen");
    keys.insert("clear");
    keys.insert("server");
    keys.insert("sections");
    keys.insert("deviceinfo");
    keys.insert("ohtestfps");
    keys.insert("editorServer");

    for (auto a : OHOS::SmartPerf::COMMAND_MAP) {
        keys.insert(a.first.substr(1)); // No prefix required '-'
    }

    auto itr = keys.find("f1");
    if (keys.end() != itr) {
        keys.erase(itr);
    }
    itr = keys.find("f2");
    if (keys.end() != itr) {
        keys.erase(itr);
    }
    itr = keys.find("fl");
    if (keys.end() != itr) {
        keys.erase(itr);
    }
    itr = keys.find("ftl");
    if (keys.end() != itr) {
        keys.erase(itr);
    }
    return OHOS::SmartPerf::SPUtils::VeriyParameter(keys, str, errorInfo);
}

/**
 * @tc.name: GetOptionsTestCase
 * @tc.desc: Test GetOptions
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonMainTest, GetOptionsTestCase001, TestSize.Level1)
{
    bool ret = false;

    std::vector<std::string> argv;
    argv.push_back("Test");
    argv.push_back("GetOptions");
    argv.push_back("SP_daemon");
    argv.push_back("-start");
    argv.push_back("-c");

    std::string str = g_getOptions(argv);

    if (!str.empty()) {
        ret = true;
    }

    EXPECT_TRUE(ret);
}

HWTEST_F(SPdaemonMainTest, CheckCMDParamTestCase002, TestSize.Level1)
{
    std::string errorInfo = "";
    std::vector<std::string> argv;
    argv.push_back("SP_daemon");
    argv.push_back("-start");
    argv.push_back("-fl");
    argv.push_back("-ftl");

    bool ret = CheckCMDParam(argv, errorInfo);
    EXPECT_EQ(ret, false);
}

HWTEST_F(SPdaemonMainTest, CheckCMDParamTestCase003, TestSize.Level1)
{
    std::string errorInfo = "";
    std::vector<std::string> argv;
    argv.push_back("SP_daemon");
    argv.push_back("");

    bool ret = CheckCMDParam(argv, errorInfo);
    EXPECT_EQ(ret, true);
}

}
}