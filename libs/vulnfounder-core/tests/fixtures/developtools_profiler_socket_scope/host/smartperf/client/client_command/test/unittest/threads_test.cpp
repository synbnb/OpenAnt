/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include <regex>
#include <string>
#include "sp_utils.h"
#include "Threads.h"
using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class SPdaemonThreadsTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() {}
    void TearDown() {}
};

static bool VerifResult(const std::string &input)
{
    std::regex pattern(R"(threadsNum=([\d:|]+))");
    std::smatch match;
    if (std::regex_search(input, match, pattern)) {
        if (match.size() > 1) {
            std::cout << match[1].str() << std::endl;
            return !match[1].str().empty();
        }
    }

    return false;
}
/**
 * @tc.name: ThreadsTestCase01
 * @tc.desc: Test Threads by packagename
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonThreadsTest, ThreadsTestCase01, TestSize.Level1)
{
    std::string cmd = "SP_daemon -N 1 -PKG ohos.samples.ecg -threads";
    std::string result = "";
    bool flag = false;
    bool ret = SPUtils::LoadCmd(cmd, result);
    std::string::size_type strOne = result.find("command exec finished!");
    if ((strOne != result.npos)) {
        flag = true;
    }
    EXPECT_EQ(ret, true);
    EXPECT_TRUE(flag);
}

/**
 * @tc.name: ThreadsTestCase03
 * @tc.desc: Test Threads by pid not exit
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonThreadsTest, ThreadsTestCase03, TestSize.Level1)
{
    std::string cmd = "SP_daemon -N 1 -threads -PID 88888888"; // 88888888 is not exit
    std::string result = "";
    bool ret = SPUtils::LoadCmd(cmd, result);
    EXPECT_EQ(ret, true);
    ret = VerifResult(result);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: ThreadsTestCase04
 * @tc.desc: Test Threads
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonThreadsTest, ThreadsTestCase04, TestSize.Level1)
{
    Threads &ths = Threads::GetInstance();
    std::string packName = "init";
    ths.SetPackageName(packName);
    ths.SetProcessId("1");
    std::map<std::string, std::string> thsItemData = ths.ItemData();
    std::string threadsNum = thsItemData["threadsNum"];
    EXPECT_EQ(threadsNum.empty(), false);
}
} // namespace OHOS
} // namespace SmartPerf