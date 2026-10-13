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
#include <string>
#include <map>
#include "shader.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class ShaderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ShaderTest::SetUpTestCase(void)
{
}

void ShaderTest::TearDownTestCase(void)
{
}

void ShaderTest::SetUp()
{
}

void ShaderTest::TearDown()
{
}

/**
 * @tc.name: ShaderTest_SetPkgName_001
 * @tc.desc: Verify SetPkgName sets package name correctly with valid input
 * @tc.type: FUNC
 */
HWTEST_F(ShaderTest, ShaderTest_SetPkgName_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ShaderTest-begin ShaderTest_SetPkgName_001";
    Shader &shader = Shader::GetInstance();
    std::string testPkgName = "com.example.testapp";
    
    shader.SetPkgName(testPkgName);
    
    std::map<std::string, std::string> result = shader.ItemData();
    EXPECT_FALSE(result.count("compileNum") > 0);
    EXPECT_FALSE(result.count("compileDuration") > 0);
    GTEST_LOG_(INFO) << "ShaderTest-end ShaderTest_SetPkgName_001";
}

/**
 * @tc.name: ShaderTest_SetPkgName_002
 * @tc.desc: Verify SetPkgName handles empty package name
 * @tc.type: FUNC
 */
HWTEST_F(ShaderTest, ShaderTest_SetPkgName_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ShaderTest-begin ShaderTest_SetPkgName_002";
    Shader &shader = Shader::GetInstance();
    std::string emptyPkgName = "";
    
    shader.SetPkgName(emptyPkgName);
    
    std::map<std::string, std::string> result = shader.ItemData();
    EXPECT_FALSE(result.count("compileNum") > 0);
    EXPECT_FALSE(result.count("compileDuration") > 0);
    GTEST_LOG_(INFO) << "ShaderTest-end ShaderTest_SetPkgName_002";
}

/**
 * @tc.name: ShaderTest_GetInstance_001
 * @tc.desc: Verify GetInstance returns singleton instance
 * @tc.type: FUNC
 */
HWTEST_F(ShaderTest, ShaderTest_GetInstance_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ShaderTest-begin ShaderTest_GetInstance_001";
    Shader &instance1 = Shader::GetInstance();
    Shader &instance2 = Shader::GetInstance();
    
    EXPECT_EQ(&instance1, &instance2);
    GTEST_LOG_(INFO) << "ShaderTest-end ShaderTest_GetInstance_001";
}

/**
 * @tc.name: ShaderTest_ItemData_002
 * @tc.desc: Verify ItemData handles non-existent package directory
 * @tc.type: FUNC
 */
HWTEST_F(ShaderTest, ShaderTest_ItemData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ShaderTest-begin ShaderTest_ItemData_001";
    Shader &shader = Shader::GetInstance();
    shader.SetPkgName("com.example.nonexistent");
    
    std::map<std::string, std::string> result = shader.ItemData();
    
    EXPECT_FALSE(result.count("compileNum") > 0);
    EXPECT_FALSE(result.count("compileDuration") > 0);
    GTEST_LOG_(INFO) << "ShaderTest-end ShaderTest_ItemData_001";
}

/**
 * @tc.name: ShaderTest_ItemData_003
 * @tc.desc: Verify ItemData returns correct map structure with valid package name
 * @tc.type: FUNC
 */
HWTEST_F(ShaderTest, ShaderTest_ItemData_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ShaderTest-begin ShaderTest_ItemData_002";
    Shader &shader = Shader::GetInstance();
    shader.SetPkgName("com.example.test");
    
    std::map<std::string, std::string> result = shader.ItemData();
    
    EXPECT_FALSE(result.count("compileNum") > 0);
    EXPECT_FALSE(result.count("compileDuration") > 0);
    EXPECT_TRUE(result.size() >= 2);
    GTEST_LOG_(INFO) << "ShaderTest-end ShaderTest_ItemData_002";
}
}
}
