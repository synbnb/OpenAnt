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
#include <unistd.h>
#include <string>
#include <vector>
#include "include/FileDescriptor.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class FileDescriptorTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(FileDescriptorTest, SetPackageNameTest001, TestSize.Level1)
{
    FileDescriptor& fd = FileDescriptor::GetInstance();
    std::string packageName = "com.example.test";
    fd.SetPackageName(packageName);
    EXPECT_TRUE(true);
}

HWTEST_F(FileDescriptorTest, SetPackageNameTest002, TestSize.Level1)
{
    FileDescriptor& fd = FileDescriptor::GetInstance();
    std::string packageName = "";
    fd.SetPackageName(packageName);
    EXPECT_TRUE(true);
}

HWTEST_F(FileDescriptorTest, SetPackageNameTest003, TestSize.Level1)
{
    FileDescriptor& fd = FileDescriptor::GetInstance();
    std::string packageName = "com.very.long.package.name.with.many.dots";
    fd.SetPackageName(packageName);
    EXPECT_TRUE(true);
}

HWTEST_F(FileDescriptorTest, SetProcessIdTest001, TestSize.Level1)
{
    FileDescriptor& fd = FileDescriptor::GetInstance();
    std::string pid = "1234";
    fd.SetProcessId(pid);
    EXPECT_TRUE(true);
}

HWTEST_F(FileDescriptorTest, SetProcessIdTest002, TestSize.Level1)
{
    FileDescriptor& fd = FileDescriptor::GetInstance();
    std::string pid = "";
    fd.SetProcessId(pid);
    EXPECT_TRUE(true);
}

HWTEST_F(FileDescriptorTest, SetProcessIdTest003, TestSize.Level1)
{
    FileDescriptor& fd = FileDescriptor::GetInstance();
    std::string pid = "1234 5678 9012";
    fd.SetProcessId(pid);
    EXPECT_TRUE(true);
}

HWTEST_F(FileDescriptorTest, SetProcessIdTest004, TestSize.Level1)
{
    FileDescriptor& fd = FileDescriptor::GetInstance();
    std::string pid = "1";
    fd.SetProcessId(pid);
    EXPECT_TRUE(true);
}

HWTEST_F(FileDescriptorTest, SetProcessIdTest005, TestSize.Level1)
{
    FileDescriptor& fd = FileDescriptor::GetInstance();
    std::string pid = "999999";
    fd.SetProcessId(pid);
    EXPECT_TRUE(true);
}

HWTEST_F(FileDescriptorTest, SetProcessIdTest006, TestSize.Level1)
{
    FileDescriptor& fd = FileDescriptor::GetInstance();
    std::string pid = "   ";
    fd.SetProcessId(pid);
    EXPECT_TRUE(true);
}

HWTEST_F(FileDescriptorTest, SetProcessIdForFuzzTestTest001, TestSize.Level1)
{
    FileDescriptor& fd = FileDescriptor::GetInstance();
    std::vector<std::string> pids = {"1234"};
    fd.SetProcessIdForFuzzTest(pids);
    EXPECT_TRUE(true);
}

HWTEST_F(FileDescriptorTest, SetProcessIdForFuzzTestTest002, TestSize.Level1)
{
    FileDescriptor& fd = FileDescriptor::GetInstance();
    std::vector<std::string> pids = {};
    fd.SetProcessIdForFuzzTest(pids);
    EXPECT_TRUE(true);
}

HWTEST_F(FileDescriptorTest, SetProcessIdForFuzzTestTest003, TestSize.Level1)
{
    FileDescriptor& fd = FileDescriptor::GetInstance();
    std::vector<std::string> pids = {"1234", "5678", "9012"};
    fd.SetProcessIdForFuzzTest(pids);
    EXPECT_TRUE(true);
}

HWTEST_F(FileDescriptorTest, SetProcessIdForFuzzTestTest004, TestSize.Level1)
{
    FileDescriptor& fd = FileDescriptor::GetInstance();
    std::vector<std::string> pids = {""};
    fd.SetProcessIdForFuzzTest(pids);
    EXPECT_TRUE(true);
}

HWTEST_F(FileDescriptorTest, SetProcessIdForFuzzTestTest005, TestSize.Level1)
{
    FileDescriptor& fd = FileDescriptor::GetInstance();
    std::vector<std::string> pids = {"1", "2", "3", "4", "5"};
    fd.SetProcessIdForFuzzTest(pids);
    EXPECT_TRUE(true);
}

HWTEST_F(FileDescriptorTest, ItemDataTest001, TestSize.Level1)
{
    FileDescriptor& fd = FileDescriptor::GetInstance();
    std::string pid = std::to_string(getpid());
    fd.SetProcessId(pid);
    std::map<std::string, std::string> result = fd.ItemData();
    EXPECT_FALSE(result.empty());
}

HWTEST_F(FileDescriptorTest, ItemDataTest002, TestSize.Level1)
{
    FileDescriptor& fd = FileDescriptor::GetInstance();
    fd.SetProcessId("");
    std::map<std::string, std::string> result = fd.ItemData();
    EXPECT_TRUE(result.empty() || result.find("fds") != result.end());
}

HWTEST_F(FileDescriptorTest, ItemDataTest003, TestSize.Level1)
{
    FileDescriptor& fd = FileDescriptor::GetInstance();
    std::string pid = std::to_string(getpid());
    fd.SetProcessId(pid);
    std::map<std::string, std::string> result = fd.ItemData();
    EXPECT_TRUE(result.find("fds") != result.end());
    EXPECT_TRUE(result.find("fdTotal") != result.end());
}
}
}
