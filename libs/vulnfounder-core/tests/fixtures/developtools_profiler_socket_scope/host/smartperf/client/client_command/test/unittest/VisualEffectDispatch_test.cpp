/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with与其他文件测试 License.
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

#include <string>
#include <map>
#include <memory>
#include <functional>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "include/VisualEffectDisPatch.h"

using namespace testing::ext;
using namespace OHOS::SmartPerf;

namespace {
class VisualEffectDisPatchTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(VisualEffectDisPatchTest, GameScheduleEventCallbackImpl_OnGameScheduleEvent_001, TestSize.Level1)
{
    GameScheduleEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";
    params["key2"] = "value2";

    VisualEffectDisPatch::GetInstance().SetSpeciFlag();
    VisualEffectDisPatch::GetInstance().SetCatchTraceFlag();

    int32_t result = callback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 1);

    std::map<std::string, std::string> itemData = VisualEffectDisPatch::GetInstance().ItemData();
    EXPECT_EQ(itemData["key1"], "value1");
    EXPECT_EQ(itemData["key2"], "value2");
}

HWTEST_F(VisualEffectDisPatchTest, GameScheduleEventCallbackImpl_OnGameScheduleEvent_002, TestSize.Level1)
{
    GameScheduleEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["testKey"] = "testValue";

    VisualEffectDisPatch::GetInstance().SetSpeciFlag();

    int32_t result = callback.OnGameScheduleEvent(2, params);

    EXPECT_EQ(result, 1);
}

HWTEST_F(VisualEffectDisPatchTest, GameScheduleEventCallbackImpl_OnGameScheduleEvent_003, TestSize.Level1)
{
    GameScheduleEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    VisualEffectDisPatch::GetInstance().SetCatchTraceFlag();

    int32_t result = callback.OnGameScheduleEvent(3, params);

    EXPECT_EQ(result, 2);
}

HWTEST_F(VisualEffectDisPatchTest, GameScheduleEventCallbackImpl_OnGameScheduleEvent_004, TestSize.Level1)
{
    GameScheduleEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    int32_t result = callback.OnGameScheduleEvent(4, params);

    EXPECT_EQ(result, 0);
}

HWTEST_F(VisualEffectDisPatchTest, GameScheduleEventCallbackImpl_OnGameScheduleEvent_005, TestSize.Level1)
{
    GameScheduleEventCallbackImpl callback;
    std::map<std::string, std::string> params;

    int32_t result = callback.OnGameScheduleEvent(0, params);

    EXPECT_EQ(result, (0));
}

HWTEST_F(VisualEffectDisPatchTest, GameScheduleEventCallbackImpl_OnGameScheduleEvent_006, TestSize.Level1)
{
    GameScheduleEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["empty"] = "";

    int32_t result = callback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 0);
}

HWTEST_F(VisualEffectDisPatchTest, GameScheduleEventCallbackImpl_OnGameScheduleEvent_007, TestSize.Level1)
{
    GameScheduleEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    for (int i = 0; i < 100; i++) {
        params["key" + std::to_string(i)] = "value" + std::to_string(i);
    }

    int32_t result = callback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 0);

    std::map<std::string, std::string> itemData =VisualEffectDisPatch::GetInstance().ItemData();
    EXPECT_EQ(itemData.size(), 100);
}

HWTEST_F(VisualEffectDisPatchTest, GameScheduleEventCallbackImpl_OnGameScheduleEvent_008, TestSize.Level1)
{
    GameScheduleEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["special_key"] = "special_value_with_special_chars_!@#$%^&*()";

    int32_t result = callback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 0);

    std::map<std::string, std::string> itemData = VisualEffectDisPatch::GetInstance().ItemData();
    EXPECT_EQ(itemData["special_key"], "special_value_with_special_chars_!@#$%^&*()");
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_ItemData_001, TestSize.Level1)
{
    VisualEffectDisPatch::GetInstance().GetVisualEffectDisPatchItemData()["test"] = "value";

    std::map<std::string, std::string> result = VisualEffectDisPatch::GetInstance().ItemData();

    EXPECT_EQ(result["test"], "value");
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_ItemData_002, TestSize.Level1)
{
    std::map<std::string, std::string> result = VisualEffectDisPatch::GetInstance().ItemData();

    EXPECT_TRUE(result.empty());
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_ItemData_003, TestSize.Level1)
{
    auto& itemData = VisualEffectDisPatch::GetInstance().GetVisualEffectDisPatchItemData();
    itemData["key1"] = "value1";
    itemData["key2"] = "value2";
    itemData["key3"] = "value3";

    std::map<std::string, std::string> result = VisualEffectDisPatch::GetInstance().ItemData();

    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result["key1"], "value1");
    EXPECT_EQ(result["key2"], "value2");
    EXPECT_EQ(result["key3"], "value3");
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_GetVisualEffectDisPatchItemData_001, TestSize.Level1)
{
    std::map<std::string, std::string>& result =
        VisualEffectDisPatch::GetInstance().GetVisualEffectDisPatchItemData();

    result["test"] = "value";

    std::map<std::string, std::string>& result2 =
        VisualEffectDisPatch::GetInstance().GetVisualEffectDisPatchItemData();

    EXPECT_EQ(result2["test"], "value");
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_GetVisualEffectDisPatchItemData_002, TestSize.Level1)
{
    std::map<std::string, std::string>& result =
        VisualEffectDisPatch::GetInstance().GetVisualEffectDisPatchItemData();

    EXPECT_TRUE(result.empty());
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_GetVisualEffectDisPatchItemData_003, TestSize.Level1)
{
    std::map<std::string, std::string>& result =
        VisualEffectDisPatch::GetInstance().GetVisualEffectDisPatchItemData();
    result["key1"] = "value1";

    result.clear();

    std::map<std::string, std::string>& result2 =
        VisualEffectDisPatch::GetInstance().GetVisualEffectDisPatchItemData();

    EXPECT_TRUE(result2.empty());
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_RegisterGameScheduleEvent_001, TestSize.Level1)
{
    int result = VisualEffectDisPatch::GetInstance().RegisterGameScheduleEvent();

    EXPECT_EQ(result, -1);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_RegisterGameScheduleEvent_002, TestSize.Level1)
{
    int result1 = VisualEffectDisPatch::GetInstance().RegisterGameScheduleEvent();

    int result2 = VisualEffectDisPatch::GetInstance().RegisterGameScheduleEvent();

    EXPECT_EQ(result2, 0);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_RegisterGameScheduleEvent_003, TestSize.Level1)
{
    int result = VisualEffectDisPatch::GetInstance().RegisterGameScheduleEvent();

    VisualEffectDisPatch::GetInstance().UnregisterGameEvent();

    int result2 = VisualEffectDisPatch::GetInstance().RegisterGameScheduleEvent();

    EXPECT_EQ(result2, -1);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_UnregisterGameEvent_001, TestSize.Level1)
{
    int result = VisualEffectDisPatch::GetInstance().UnregisterGameEvent();

    EXPECT_EQ(result, 0);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_UnregisterGameEvent_002, TestSize.Level1)
{
    VisualEffectDisPatch::GetInstance().RegisterGameScheduleEvent();

    int result = VisualEffectDisPatch::GetInstance().UnregisterGameEvent();

    EXPECT_EQ(result, -1);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_UnregisterGameEvent_003, TestSize.Level1)
{
    VisualEffectDisPatch::GetInstance().UnregisterGameEvent();

    int result = VisualEffectDisPatch::GetInstance().UnregisterGameEvent();

    EXPECT_EQ(result, 0);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_UnregisterGameEvent_004, TestSize.Level1)
{
    VisualEffectDisPatch::GetInstance().RegisterGameScheduleEvent();

    VisualEffectDisPatch::GetInstance().UnregisterGameEvent();

    int result = VisualEffectDisPatch::GetInstance().UnregisterGameEvent();

    EXPECT_EQ(result, 0);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_SetSpeciFlag_001, TestSize.Level1)
{
    VisualEffectDisPatch::GetInstance().SetSpeciFlag();

    bool result = VisualEffectDisPatch::GetInstance().GetSpeciFlag();

    EXPECT_TRUE(result);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_SetSpeciFlag_002, TestSize.Level1)
{
    VisualEffectDisPatch::GetInstance().SetSpeciFlag();

    VisualEffectDisPatch::GetInstance().SetSpeciFlag();

    bool result = VisualEffectDisPatch::GetInstance().GetSpeciFlag();

    EXPECT_TRUE(result);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_SetCatchTraceFlag_001, TestSize.Level1)
{
    VisualEffectDisPatch::GetInstance().SetCatchTraceFlag();

    bool result = VisualEffectDisPatch::GetInstance().GetCatchTraceFlag();

    EXPECT_TRUE(result);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_SetCatchTraceFlag_002, TestSize.Level1)
{
    VisualEffectDisPatch::GetInstance().SetCatchTraceFlag();

    VisualEffectDisPatch::GetInstance().SetCatchTraceFlag();

    bool result = VisualEffectDisPatch::GetInstance().GetCatchTraceFlag();

    EXPECT_TRUE(result);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_GetSpeciFlag_001, TestSize.Level1)
{
    bool result = VisualEffectDisPatch::GetInstance().GetSpeciFlag();

    EXPECT_FALSE(result);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_GetSpeciFlag_002, TestSize.Level1)
{
    VisualEffectDisPatch::GetInstance().SetSpeciFlag();

    bool result = VisualEffectDisPatch::GetInstance().GetSpeciFlag();

    EXPECT_TRUE(result);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_GetCatchTraceFlag_001, TestSize.Level1)
{
    bool result = VisualEffectDisPatch::GetInstance().GetCatchTraceFlag();

    EXPECT_FALSE(result);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_GetCatchTraceFlag_002, TestSize.Level1)
{
    VisualEffectDisPatch::GetInstance().SetCatchTraceFlag();

    bool result = VisualEffectDisPatch::GetInstance().GetCatchTraceFlag();

    EXPECT_TRUE(result);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_Integration_001, TestSize.Level1)
{
    VisualEffectDisPatch::GetInstance().SetSpeciFlag();

    GameScheduleEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["test"] = "value";

    int32_t result = callback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 1);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_Integration_002, TestSize.Level1)
{
    VisualEffectDisPatch::GetInstance().SetCatchTraceFlag();

    GameScheduleEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["test"] = "value";

    int32_t result = callback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 2);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_Integration_003, TestSize.Level1)
{
    VisualEffectDisPatch::GetInstance().SetVisualEffectDisPatchType(2);

    std::map<std::string, std::string> itemData =
        VisualEffectDisPatch::GetInstance().GetVisualEffectDisPatchItemData();
    itemData["maxCollectNum"] = "3";

    VisualEffectDisPatch::GetInstance().SetCollectNum();

    GameScheduleEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["test"] = "value";

    int32_t result = callback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 0);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_Integration_004, TestSize.Level1)
{
    VisualEffectDisPatch::GetInstance().SetVisualEffectDisPatchType(0);

    VisualEffectDisPatch::GetInstance().SetCollectNum();

    GameScheduleEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["test"] = "value";

    int32_t result = callback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 0);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_Integration_005, TestSize.Level1)
{
    VisualEffectDisPatch::GetInstance().StartExecutionOnce(false);

    VisualEffectDisPatch::GetInstance().FinishtExecutionOnce(false);

    GameScheduleEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["test"] = "value";

    int32_t result = callback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 0);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_Integration_006, TestSize.Level1)
{
    VisualEffectDisPatch::GetInstance().SetSpeciFlag();
    VisualEffectDisPatch::GetInstance().SetCatchTraceFlag();

    GameScheduleEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["test"] = "value";

    int32_t result = callback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 1);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_Integration_007, TestSize.Level1)
{
    std::map<std::string, std::string> itemData =
        VisualEffectDisPatch::GetInstance().GetVisualEffectDisPatchItemData();
    itemData["key1"] = "value1";
    itemData["key2"] = "value2";

    std::map<std::string, std::string> result = VisualEffectDisPatch::GetInstance().ItemData();

    EXPECT_EQ(result.size(), 2);
    EXPECT_EQ(result["key1"], "value1");
    EXPECT_EQ(result["key2"], "value2");
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_EdgeCase_001, TestSize.Level1)
{
    GameScheduleEventCallbackImpl callback;
    std::map<std::string, std::string> params;

    int32_t result = callback.OnGameScheduleEvent(2147483647, params);

    EXPECT_EQ(result, 0);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_EdgeCase_002, TestSize.Level1)
{
    GameScheduleEventCallbackImpl callback;
    std::map<std::string, std::string> params;

    int32_t result = callback.OnGameScheduleEvent(-2147483648, params);

    EXPECT_EQ(result, 0);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_EdgeCase_005, TestSize.Level1)
{
    std::map<std::string, std::string>& itemData =
        VisualEffectDisPatch::GetInstance().GetVisualEffectDisPatchItemData();
    std::string longKey(1000, 'a');
    std::string longValue(1000, 'b');
    itemData[longKey] = longValue;

    std::map<std::string, std::string> result = VisualEffectDisPatch::GetInstance().ItemData();

    EXPECT_EQ(result[longKey], longValue);
}

HWTEST_F(VisualEffectDisPatchTest, VisualEffectDisPatch_EdgeCase_006, TestSize.Level1)
{
    std::map<std::string, std::string>& itemData =
        VisualEffectDisPatch::GetInstance().GetVisualEffectDisPatchItemData();
    for (int i = 0; i < 1000; i++) {
        itemData["key" + std::to_string(i)] = "value" + std::to_string(i);
    }

    std::map<std::string, std::string> result = VisualEffectDisPatch::GetInstance().ItemData();

    EXPECT_EQ(result.size(), 1000);
}
}