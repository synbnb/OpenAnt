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

#include <string>
#include <map>
#include <memory>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "interface/GameScheduleEventCallBack.h"

using namespace testing::ext;
using namespace OHOS::SmartPerf;

namespace {
class MockGameScheduleEventCallback : public GameScheduleEventCallback {
public:
    MOCK_METHOD(int32_t, OnGameScheduleEvent, (int32_t type, std::map<std::string, std::string> &params), (override));
};

class GameScheduleEventCallbackTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_001, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";
    params["key2"] = "value2";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(0));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 0);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_002, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["testKey"] = "testValue";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(2, testing::Ref(params)))
        .WillOnce(testing::Return(1));

    int32_t result = mockCallback.OnGameScheduleEvent(2, params);

    EXPECT_EQ(result, 1);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_003, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(3, testing::Ref(params)))
        .WillOnce(testing::Return(2));

    int32_t result = mockCallback.OnGameScheduleEvent(3, params);

    EXPECT_EQ(result, 2);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_004, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(4, testing::Ref(params)))
        .WillOnce(testing::Return(-1));

    int32_t result = mockCallback.OnGameScheduleEvent(4, params);

    EXPECT_EQ(result, -1);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_005, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(0, testing::Ref(params)))
        .WillOnce(testing::Return(0));

    int32_t result = mockCallback.OnGameScheduleEvent(0, params);

    EXPECT_EQ(result, 0);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_006, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["empty"] = "";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(0));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 0);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_007, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    for (int i = 0; i < 100; i++) {
        params["key" + std::to_string(i)] = "value" + std::to_string(i);
    }

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(0));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 0);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_008, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["special_key"] = "special_value_with_special_chars_!@#$%^&*()";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(0));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 0);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_009, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .Times(2)
        .WillRepeatedly(testing::Return(0));

    int32_t result1 = mockCallback.OnGameScheduleEvent(1, params);
    int32_t result2 = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result1, 0);
    EXPECT_EQ(result2, 0);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_010, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(0))
        .WillOnce(testing::Return(1));

    int32_t result1 = mockCallback.OnGameScheduleEvent(1, params);
    int32_t result2 = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result1, 0);
    EXPECT_EQ(result2, 1);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_011, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(testing::_, testing::Ref(params)))
        .WillOnceWithArgs([](int32_t type, std::map<std::string, std::string>&) {
            return type * 2;
        });

    int32_t result = mockCallback.OnGameScheduleEvent(5, params);

    EXPECT_EQ(result, 10);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_012, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(testing::_, testing::_))
        .WillOnceWithArgs([](int32_t type, std::map<std::string, std::string>& params) {
            return static_cast<int32_t>(params.size());
        });

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 1);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_013, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";
    params["key2"] = "value2";
    params["key3"] = "value3";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(3));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 3);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_014, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::DoAll(
            testing::WithArgs<1>([](std::map<std::string, std::string>& params) {
                params["key2"] = "value2";
            }),
            testing::Return(0)
        ));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 0);
    EXPECT_EQ(params.size(), 2);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_015, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(100));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 100);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_016, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(-100));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, -100);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_017, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(2147483647));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 2147483647);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_018, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(-2147483648));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, -2147483648);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_019, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(0));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 0);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_020, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(1));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 1);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_021, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(2));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 2);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_022, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(3));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 3);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_023, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(4));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 4);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_024, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(5));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 5);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_025, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(10));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 10);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_026, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(20));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 20);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_027, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(50));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 50);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_028, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(100));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 100);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_029, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(200));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 200);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_030, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(500));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 500);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_031, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(1000));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 1000);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_032, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(2000));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 2000);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_033, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(5000));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 5000);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_034, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(10000));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 10000);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_035, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(20000));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 20000);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_036, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(50000));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 50000);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_037, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(100000));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 100000);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_038, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(200000));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 200000);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_039, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(500000));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 500000);
}

HWTEST_F(GameScheduleEventCallbackTest, GameScheduleEventCallback_OnGameScheduleEvent_040, TestSize.Level1)
{
    MockGameScheduleEventCallback mockCallback;
    std::map<std::string, std::string> params;
    params["key1"] = "value1";

    EXPECT_CALL(mockCallback, OnGameScheduleEvent(1, testing::Ref(params)))
        .WillOnce(testing::Return(1000000));

    int32_t result = mockCallback.OnGameScheduleEvent(1, params);

    EXPECT_EQ(result, 1000000);
}

}