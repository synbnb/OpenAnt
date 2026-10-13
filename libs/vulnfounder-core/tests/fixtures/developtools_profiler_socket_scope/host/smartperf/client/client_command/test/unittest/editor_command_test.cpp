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
#include "unistd.h"
#include <thread>
#include <cstdio>
#include <cstring>
#include <map>
#include <gtest/gtest.h>
#include <sstream>
#include "editor_command.h"
#include "control_call_cmd.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class EditorCommandTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(EditorCommandTest, EditorCommandTest01, TestSize.Level1)
{
    int argc = 2;
    std::vector<std::string> argv = {"arg1", "arg2"};
    EditorCommand editorCommand(argc, argv);
    ASSERT_TRUE(true);
}
}
}