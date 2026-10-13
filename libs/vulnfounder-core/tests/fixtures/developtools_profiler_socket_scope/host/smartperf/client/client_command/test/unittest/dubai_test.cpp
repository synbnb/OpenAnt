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
#include "sp_utils.h"
#include "parse_radar.h"
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include "Dubai.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class DubaiTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(DubaiTest, DubaiBeginTest, TestSize.Level1)
{
    Dubai &dubai = Dubai::GetInstance();
    std::string result;
    auto ret = OHOS::SmartPerf::SPUtils::LoadCmd("hidumper -s 1213 -a '-b'", result);
    dubai.DumpDubaiBegin();
    
    EXPECT_EQ(ret, true);
}

HWTEST_F(DubaiTest, DubaiFinishTest, TestSize.Level1)
{
    Dubai &dubai = Dubai::GetInstance();
    std::string result;
    auto ret = OHOS::SmartPerf::SPUtils::LoadCmd("hidumper -s 1213 -a '-f'", result);
    dubai.DumpDubaiFinish();
    
    EXPECT_EQ(ret, true);
}

HWTEST_F(DubaiTest, DubaiMoveTest, TestSize.Level1)
{
    Dubai &dubai = Dubai::GetInstance();
    std::string result;
    const std::string dubaiXpower = "/data/service/el2/100/xpower/dubai.db";
    const std::string database = "/data/app/el2/100/database/";
    const std::string pkgEntry = "/entry/rdb";
    const std::string cpDubai = "cp " + dubaiXpower + " " + database + dubai.dubaiPkgName + pkgEntry;
    const std::string dubaiPathChmod = "chmod 777 " + database + dubai.dubaiPkgName + pkgEntry + "/dubai.db";
    if (!dubai.IsFileAccessible(dubaiXpower)) {
        sleep(1);
    }
    auto retCp = OHOS::SmartPerf::SPUtils::LoadCmd(cpDubai, result);
    auto retChmod = OHOS::SmartPerf::SPUtils::LoadCmd(dubaiPathChmod, result);
    dubai.MoveDubaiDb();

    EXPECT_EQ(retCp, true);
    EXPECT_EQ(retChmod, true);
}

HWTEST_F(DubaiTest, CallMoveDubaiDbFinished01, TestSize.Level1)
{
    OHOS::SmartPerf::Dubai::isDumpDubaiFinish = false;
    std::string result = OHOS::SmartPerf::Dubai::GetInstance().CallMoveDubaiDbFinished();
    EXPECT_EQ(result, "get_dubai_db");
}

HWTEST_F(DubaiTest, CallMoveDubaiDbFinished02, TestSize.Level1)
{
    OHOS::SmartPerf::Dubai::isDumpDubaiFinish = true;
    std::string result = OHOS::SmartPerf::Dubai::GetInstance().CallMoveDubaiDbFinished();
    EXPECT_EQ(result, "get_dubai_db");
}

HWTEST_F(DubaiTest, IsFileAccessible01, TestSize.Level1)
{
    std::string existingFile = "existing_file.txt";
    std::ofstream file(existingFile);
    file << "Test content";
    file.close();
    bool result = Dubai::GetInstance().IsFileAccessible(existingFile);
    EXPECT_TRUE(result);
    std::remove(existingFile.c_str());
}

HWTEST_F(DubaiTest, IsFileAccessible02, TestSize.Level1)
{
    std::string nonExistingFile = "non_existing_file.txt";
    bool result = Dubai::GetInstance().IsFileAccessible(nonExistingFile);
    EXPECT_FALSE(result);
}
}
}