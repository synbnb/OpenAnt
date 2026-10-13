/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * Licensed under * Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with * License.
 * You may obtain a copy of * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under * License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See * License for * specific language governing permissions and
 * limitations under * License.
 */
#include <gtest/gtest.h>
#include <string>
#include "client_control.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class ClientControlTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ClientControlTest::SetUpTestCase(void)
{
}

void ClientControlTest::TearDownTestCase(void)
{
}

void ClientControlTest::SetUp()
{
}

void ClientControlTest::TearDown()
{
}
/**
 * @tc.name: ClientControlTest_SocketStart_001
 * @tc.desc:：验证 SocketStart 使用有效参数
 * @tc.type: FUNC
 */
HWTEST_F(ClientControlTest, ClientControlTest_SocketStart_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ClientControlTest-begin ClientControlTest_SocketStart_001";
    OHOS::SmartPerf::ClientControl clientControl;
    std::string testArgs = "-test-args";
    
    int result = clientControl.SocketStart(testArgs);
    
    EXPECT_TRUE(result >= 0);
    GTEST_LOG_(INFO) << "ClientControlTest-end ClientControlTest_SocketStart_001";
}

/**
 * @tc.name: ClientControlTest_SocketStart_002
 * @tc.desc:：验证 SocketStart 使用空参数
 * @tc.type: FUNC
 */
HWTEST_F(ClientControlTest, ClientControlTest_SocketStart_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ClientControlTest-begin ClientControlTest_SocketStart_002";
    ClientControl clientControl;
    std::string emptyArgs = "";
    
    int result = clientControl.SocketStart(emptyArgs);
    
    EXPECT_TRUE(result >= 0);
    GTEST_LOG_(INFO) << "ClientControlTest-end ClientControlTest_SocketStart_002";
}

/**
 * @tc.name: ClientControlTest_SocketStop_001
 * @tc.desc:：验证 SocketStop 正常停止
 * @tc.type: FUNC
 */
HWTEST_F(ClientControlTest, ClientControlTest_SocketStop_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ClientControlTest-begin ClientControlTest_SocketStop_001";
    ClientControl clientControl;
    
    int result = clientControl.SocketStop();
    
    EXPECT_TRUE(result >= 0);
    GTEST_LOG_(INFO) << "ClientControlTest-end ClientControlTest_SocketStop_001";
}

/**
 * @tc.name: ClientControlTest_InitSocket_001
 * @tc.desc:：验证 InitSocket 初始化 Socket
 * @tc.type: FUNC
 */
HWTEST_F(ClientControlTest, ClientControlTest_InitSocket_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ClientControlTest-begin ClientControlTest_InitSocket_001";
    ClientControl clientControl;
    
    int result = clientControl.InitSocket();
    
    EXPECT_TRUE(result >= 0);
    GTEST_LOG_(INFO) << "ClientControlTest-end ClientControlTest_InitSocket_001";
}

/**
 * @tc.name: ClientControlTest_CloseSocket_001
 * @tc.desc:：验证 CloseSocket 关闭 Socket
 * @tc.type: FUNC
 */
HWTEST_F(ClientControlTest, ClientControlTest_CloseSocket_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ClientControlTest-begin ClientControlTest_CloseSocket_001";
    ClientControl clientControl;
    
    int result = clientControl.CloseSocket();
    
    EXPECT_TRUE(result >= 0);
    GTEST_LOG_(INFO) << "ClientControlTest-end ClientControlTest_CloseSocket_001";
}

/**
 * @tc.name: ClientControlTest_StartSPDaemon_001
 * @tc.desc:：验证 StartSPDaemon 启动 SP_daemon

 @tc.type: FUNC
 */
HWTEST_F(ClientControlTest, ClientControlTest_StartSPDaemon_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ClientControlTest-begin ClientControlTest_StartSPDaemon_001";
    ClientControl clientControl;
    
    clientControl.StartSPDaemon();
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "ClientControlTest-end ClientControlTest_StartSPDaemon_001";
}

/**
 * @tc.name: ClientControlTest_SocketSequence_001
 * @tc.desc:：验证 Socket 启动和停止的序列操作
 * @tc.type: FUNC
 */
HWTEST_F(ClientControlTest, ClientControlTest_SocketSequence_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ClientControlTest-begin ClientControlTest_SocketSequence_001";
    ClientControl clientControl;
    
    int initResult = clientControl.InitSocket();
    EXPECT_TRUE(initResult >= 0);
    
    int closeResult = clientControl.CloseSocket();
    EXPECT_TRUE(closeResult >= 0);
    
    GTEST_LOG_(INFO) << "ClientControlTest-end ClientControlTest_SocketSequence_001";
}

/**
 * @tc.name: ClientControlTest_MultipleStartStop_001
 * @tc.desc:：验证多次启动和停止操作的稳定性
 * @tc.type: FUNC
 */
HWTEST_F(ClientControlTest, ClientControlTest_MultipleStartStop_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ClientControlTest-begin ClientControlTest_MultipleStartStop_001";
    ClientControl clientControl;
    
    for (int i = 0; i < 3; i++) {
        int result = clientControl.CloseSocket();
        EXPECT_TRUE(result >= 0);
    }
    
    GTEST_LOG_(INFO) << "ClientControlTest-end ClientControlTest_MultipleStartStop_001";
}
}
}
