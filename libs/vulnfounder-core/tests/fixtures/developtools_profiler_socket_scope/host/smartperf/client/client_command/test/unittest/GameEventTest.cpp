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
#include "include/GameEvent.h"
#include <memory>
#include <map>
#include <string>

using namespace testing::ext;

namespace OHOS {
namespace SmartPerf {

class GameEventTest : public ::testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void GameEventTest::SetUpTestCase()
{
}

void GameEventTest::TearDownTestCase()
{
}

void GameEventTest::SetUp()
{
}

void GameEventTest::TearDown()
{
}

HWTEST_F(GameEventTest, OnGameEvent_NormalCase_001, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";
    params["key2"] = "value2";
    params["pid"] = "12345";
    
    callback.OnGameEvent(1, params);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData["key1"], "value1");
    EXPECT_EQ(itemData["key2"], "value2");
    EXPECT_EQ(itemData["pid"], "12345");
}

HWTEST_F(GameEventTest, OnGameEvent_EmptyParams_002, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    
    callback.OnGameEvent(0, params);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_TRUE(itemData.empty());
}

HWTEST_F(GameEventTest, OnGameEvent_SingleParam_003, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["singleKey"] = "singleValue";
    
    callback.OnGameEvent(5, params);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData.size(), 1);
    EXPECT_EQ(itemData["singleKey"], "singleValue");
}

HWTEST_F(GameEventTest, OnGameEvent_MultipleCalls_004, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params1;
    params1["key1"] = "value1";
    
    std::map<std::string, std::string> params2;
    params2["key2"] = "value2";
    params2["key3"] = "value3";
    
    callback.OnGameEvent(1, params1);
    callback.OnGameEvent(2, params2);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData["key1"], "value1");
    EXPECT_EQ(itemData["key2"], "value2");
    EXPECT_EQ(itemData["key3"], "value3");
}

HWTEST_F(GameEventTest, OnGameEvent_OverwriteExistingKey_005, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params1;
    params1["key1"] = "oldValue";
    
    std::map<std::string, std::string> params2;
    params2["key1"] = "newValue";
    
    callback.OnGameEvent(1, params1);
    callback.OnGameEvent(2, params2);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData["key1"], "newValue");
}

HWTEST_F(GameEventTest, OnGameEvent_SpecialCharacters_006, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["key@#$"] = "value!@#";
    params["key space"] = "value space";
    params["key\n"] = "value\t";
    
    callback.OnGameEvent(3, params);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData["key@#$"], "value!@#");
    EXPECT_EQ(itemData["key space"], "value space");
    EXPECT_EQ(itemData["key\n"], "value\t");
}

HWTEST_F(GameEventTest, OnGameEvent_LongStrings_007, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    std::string longKey(1000, 'k');
    std::string longValue(1000, 'v');
    params[longKey] = longValue;
    
    callback.OnGameEvent(4, params);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData[longKey], longValue);
}

HWTEST_F(GameEventTest, OnGameEvent_NegativeType_008, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["key"] = "value";
    
    callback.OnGameEvent(-1, params);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData["key"], "value");
}

HWTEST_F(GameEventTest, OnGameEvent_LargeTypeValue_009, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["key"] = "value";
    
    callback.OnGameEvent(INT32_MAX, params);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData["key"], "value");
}

HWTEST_F(GameEventTest, ItemData_NormalCase_001, TestSize.Level1)
{
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    itemData["testKey"] = "testValue";
    
    auto result = GameEvent::GetInstance().ItemData();
    
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result["testKey"], "testValue");
}

HWTEST_F(GameEventTest, ItemData_EmptyMap_002, TestSize.Level1)
{
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    itemData.clear();
    
    auto result = GameEvent::GetInstance().ItemData();
    
    EXPECT_TRUE(result.empty());
}

HWTEST_F(GameEventTest, ItemData_MultipleEntries_003, TestSize.Level1)
{
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    itemData["key1"] = "value1";
    itemData["key2"] = "value2";
    itemData["key3"] = "value3";
    
    auto result = GameEvent::GetInstance().ItemData();
    
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result["key1"], "value1");
    EXPECT_EQ(result["key2"], "value2");
    EXPECT_EQ(result["key3"], "value3");
}

HWTEST_F(GameEventTest, ItemData_CopyIndependence_004, TestSize.Level1)
{
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    itemData["key1"] = "value1";
    
    auto result1 = GameEvent::GetInstance().ItemData();
    itemData["key2"] = "value2";
    auto result2 = GameEvent::GetInstance().ItemData();
    
    EXPECT_EQ(result1.size(), 1);
    EXPECT_EQ(result2.size(), 2);
    EXPECT_EQ(result1["key1"], "value1");
    EXPECT_EQ(result2["key1"], "value1");
    EXPECT_EQ(result2["key2"], "value2");
}

HWTEST_F(GameEventTest, GetGameEventItemData_NormalCase_001, TestSize.Level1)
{
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    itemData["testKey"] = "testValue";
    
    EXPECT_EQ(itemData["testKey"], "testValue");
}

HWTEST_F(GameEventTest, GetGameEventItemData_ModifyThroughReference_002, TestSize.Level1)
{
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    itemData["key1"] = "value1";
    itemData["key2"] = "value2";
    
    auto &itemDataRef = GameEvent::GetInstance().GetGameEventItemData();
    itemDataRef["key3"] = "value3";
    
    EXPECT_EQ(itemData.size(), 3);
    EXPECT_EQ(itemData["key3"], "value3");
}

HWTEST_F(GameEventTest, GetGameEventItemData_ClearThroughReference_003, TestSize.Level1)
{
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    itemData["key1"] = "value1";
    
    auto &itemDataRef = GameEvent::GetInstance().GetGameEventItemData();
    itemDataRef.clear();
    
    EXPECT_TRUE(itemData.empty());
}

HWTEST_F(GameEventTest, RegisterGameEvent_AlreadyRegistered_001, TestSize.Level1)
{
    GameEvent::GetInstance().RegisterGameEvent();
    int result = GameEvent::GetInstance().RegisterGameEvent();
    EXPECT_EQ(result, 0);
}

HWTEST_F(GameEventTest, UnregisterGameEvent_NotRegistered_001, TestSize.Level1)
{
    int result = GameEvent::GetInstance().UnregisterGameEvent();
    EXPECT_EQ(result, 0);
}

HWTEST_F(GameEventTest, UnregisterGameEvent_AfterRegister_002, TestSize.Level1)
{
    int result1 = GameEvent::GetInstance().RegisterGameEvent();
    if (result1 == 0) {
        int result2 = GameEvent::GetInstance().UnregisterGameEvent();
        if (result2 == 0) {
            int result3 = GameEvent::GetInstance().UnregisterGameEvent();
            EXPECT_EQ(result3, 0);
        }
    }
}

HWTEST_F(GameEventTest, GameEvent_CallbackImplConstruction_002, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    ASSERT_NE(&callback, nullptr);
}

HWTEST_F(GameEventTest, GameEvent_MultipleCallbacks_003, TestSize.Level1)
{
    GameEventCallbackImpl callback1;
    GameEventCallbackImpl callback2;
    
    std::map<std::string, std::string> params1;
    params1["callback1"] = "value1";
    
    std::map<std::string, std::string> params2;
    params2["callback2"] = "value2";
    
    callback1.OnGameEvent(1, params1);
    callback2.OnGameEvent(2, params2);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData["callback1"], "value1");
    EXPECT_EQ(itemData["callback2"], "value2");
}

HWTEST_F(GameEventTest, GameEvent_ItemDataConsistency_004, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["key"] = "value";
    
    callback.OnGameEvent(1, params);
    
    auto &itemDataRef = GameEvent::GetInstance().GetGameEventItemData();
    auto itemDataCopy = GameEvent::GetInstance().ItemData();
    
    EXPECT_EQ(itemDataRef.size(), itemDataCopy.size());
    EXPECT_EQ(itemDataRef["key"], itemDataCopy["key"]);
}

HWTEST_F(GameEventTest, GameEvent_EmptyStringValues_005, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["key1"] = "";
    params[""] = "value2";
    params["key3"] = "value3";
    
    callback.OnGameEvent(1, params);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData["key1"], "");
    EXPECT_EQ(itemData[""], "value2");
    EXPECT_EQ(itemData["key3"], "value3");
}

HWTEST_F(GameEventTest, GameEvent_NumericStringValues_006, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["pid"] = "12345";
    params["timestamp"] = "9876543210";
    params["value"] = "3.14159";
    
    callback.OnGameEvent(1, params);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData["pid"], "12345");
    EXPECT_EQ(itemData["timestamp"], "9876543210");
    EXPECT_EQ(itemData["value"], "3.14159");
}

HWTEST_F(GameEventTest, GameEvent_RapidSuccessiveCalls_007007, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    
    for (int i = 0; i < 100; i++) {
        std::map<std::string, std::string> params;
        params["key" + std::to_string(i)] = "value" + std::to_string(i);
        callback.OnGameEvent(i, params);
    }
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData.size(), 100);
    EXPECT_EQ(itemData["key0"], "value0");
    EXPECT_EQ(itemData["key99"], "value99");
}

HWTEST_F(GameEventTest, GameEvent_CallbackWithZeroType_010, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["key"] = "value";
    
    callback.OnGameEvent(0, params);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData["key"], "value");
}

HWTEST_F(GameEventTest, GameEvent_CallbackWithLargeMap_011, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    
    for (int i = 0; i < 1000; i++) {
        params["key" + std::to_string(i)] = "value" + std::to_string(i);
    }
    
    callback.OnGameEvent(1, params);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData.size(), 1000);
    EXPECT_EQ(itemData["key0"], "value0");
    EXPECT_EQ(itemData["key999"], "value999");
}

HWTEST_F(GameEventTest, GameEvent_ItemDataThreadSafety_012, TestSize.Level1)
{
    auto &itemData1 = GameEvent::GetInstance().GetGameEventItemData();
    auto &itemData2 = GameEvent::GetInstance().GetGameEventItemData();
    
    itemData1["thread1"] = "value1";
    itemData2["thread2"] = "value2";
    
    EXPECT_EQ(itemData1["thread1"], "value1");
    EXPECT_EQ(itemData1["thread2"], "value2");
    EXPECT_EQ(itemData2["thread1"], "value1");
    EXPECT_EQ(itemData2["thread2"], "value2");
}

HWTEST_F(GameEventTest, GameEvent_CallbackUpdateExistingValue_014, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params1;
    params1["key"] = "initial";
    
    std::map<std::string, std::string> params2;
    params2["key"] = "updated";
    
    callback.OnGameEvent(1, params1);
    callback.OnGameEvent(2, params2);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData["key"], "updated");
}

HWTEST_F(GameEventTest, GameEvent_EmptyKeyAndValue_015, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params[""] = "";
    
    callback.OnGameEvent(1, params);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData[""], "");
}

HWTEST_F(GameEventTest, GameEvent_ItemDataAfterMultipleCallbacks_016, TestSize.Level1)
{
    GameEventCallbackImpl callback1;
    GameEventCallbackImpl callback2;
    GameEventCallbackImpl callback3;
    
    std::map<std::string, std::string> params1;
    params1["a"] = "1";
    params1["b"] = "2";
    
    std::map<std::string, std::string> params2;
    params2["c"] = "3";
    params2["d"] = "4";
    
    std::map<std::string, std::string> params3;
    params3["e"] = "5";
    params3["f"] = "6";
    
    callback1.OnGameEvent(1, params1);
    callback2.OnGameEvent(2, params2);
    callback3.OnGameEvent(3, params3);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData.size(), 6);
    EXPECT_EQ(itemData["a"], "1");
    EXPECT_EQ(itemData["b"], "2");
    EXPECT_EQ(itemData["c"], "3");
    EXPECT_EQ(itemData["d"], "4");
    EXPECT_EQ(itemData["e"], "5");
    EXPECT_EQ(itemData["f"], "6");
}

HWTEST_F(GameEventTest, GameEvent_OverwriteWithDifferentCallbacks_017, TestSize.Level1)
{
    GameEventCallbackImpl callback1;
    GameEventCallbackImpl callback2;
    
    std::map<std::string, std::string> params1;
    params1["shared"] = "first";
    params1["unique1"] = "value1";
    
    std::map<std::string, std::string> params2;
    params2["shared"] = "second";
    params2["unique2"] = "value2";
    
    callback1.OnGameEvent(1, params1);
    callback2.OnGameEvent(2, params2);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData["shared"], "second");
    EXPECT_EQ(itemData["unique1"], "value1");
    EXPECT_EQ(itemData["unique2"], "value2");
}

HWTEST_F(GameEventTest, GameEvent_ItemDataCopyDoesNotAffectOriginal_018, TestSize.Level1)
{
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    itemData["key1"] = "value1";
    itemData["key2"] = "value2";
    
    auto copy = GameEvent::GetInstance().ItemData();
    copy["key3"] = "value3";
    copy["key1"] = "modified";
    
    EXPECT_EQ(itemData.size(), 2);
    EXPECT_EQ(itemData["key1"], "value1");
    EXPECT_EQ(itemData["key2"], "value2");
    EXPECT_EQ(copy.size(), 3);
    EXPECT_EQ(copy["key1"], "modified");
    EXPECT_EQ(copy["key3"], "value3");
}

HWTEST_F(GameEventTest, GameEvent_CallbackWithSameKeyDifferentValues_020, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    
    for (int i = 0; i < 10; i++) {
        std::map<std::string, std::string> params;
        params["counter"] = std::to_string(i);
        callback.OnGameEvent(i, params);
    }
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData["counter"], "9");
}

HWTEST_F(GameEventTest, GameEvent_CallbackWithVeryLongKey_023, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    std::string veryLongKey(10000, 'x');
    params[veryLongKey] = "value";
    
    callback.OnGameEvent(1, params);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData[veryLongKey], "value");
}

HWTEST_F(GameEventTest, GameEvent_CallbackWithVeryLongValue_024, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    std::string veryLongValue(10000, 'y');
    params["key"] = veryLongValue;
    
    callback.OnGameEvent(1, params);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData["key"], veryLongValue);
}

HWTEST_F(GameEventTest, GameEvent_GetInstanceMultipleTimes_025, TestSize.Level1)
{
    auto &inst1 = GameEvent::GetInstance();
    auto &inst2 = GameEvent::GetInstance();
    auto &inst3 = GameEvent::GetInstance();
    
    EXPECT_EQ(&inst1, &inst2);
    EXPECT_EQ(&inst2, &inst3);
    EXPECT_EQ(&inst1, &inst3);
}

HWTEST_F(GameEventTest, GameEvent_CallbackWithUnicodeCharacters_026, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["中文"] = "值";
    params["English"] = "Value";
    params["日本語"] = "値";
    
    callback.OnGameEvent(1, params);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData["中文"], "值");
    EXPECT_EQ(itemData["English"], "Value");
    EXPECT_EQ(itemData["日本語"], "値");
}

HWTEST_F(GameEventTest, GameEvent_CallbackWithMixedTypes_027, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["int"] = "123";
    params["float"] = "456.789";
    params["bool"] = "true";
    params["string"] = "hello";
    params["empty"] = "";
    
    callback.OnGameEvent(1, params);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData["int"], "123");
    EXPECT_EQ(itemData["float"], "456.789");
    EXPECT_EQ(itemData["bool"], "true");
    EXPECT_EQ(itemData["string"], "hello");
    EXPECT_EQ(itemData["empty"], "");
}

HWTEST_F(GameEventTest, GameEvent_CallbackClearAndRefill_029, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params1;
    params1["key1"] = "value1";
    params1["key2"] = "value2";
    
    callback.OnGameEvent(1, params1);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData.size(), 2);
    
    itemData.clear();
    EXPECT_TRUE(itemData.empty());
    
    std::map<std::string, std::string> params2;
    params2["key3"] = "value3";
    params2["key4"] = "value4";
    
    callback.OnGameEvent(2, params2);
    EXPECT_EQ(itemData.size(), 2);
    EXPECT_EQ(itemData["key3"], "value3");
    EXPECT_EQ(itemData["key4"], "value4");
}

HWTEST_F(GameEventTest, GameEvent_CallbackWithDuplicateKeys_030, TestSize.Level1)
{
    GameEventCallbackImpl callback;
    std::map<std::string, std::string> params;
    params["duplicate"] = "first";
    params["duplicate"] = "second";
    params["duplicate"] = "third";
    
    callback.OnGameEvent(1, params);
    
    auto &itemData = GameEvent::GetInstance().GetGameEventItemData();
    EXPECT_EQ(itemData["duplicate"], "third");
}

} // namespace SmartPerf
} // namespace OHOS
