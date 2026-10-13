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
#include <gtest/gtest.h>
#include <map>
#include <string>
#include "sp_thread_socket.h"
#include "sp_server_socket.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class SpThreadSocketTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() {}
    void TearDown() {}
};
HWTEST_F(SpThreadSocketTest, MapToString_001, TestSize.Level1)
{
    SpThreadSocket socket;
    map<string, string> dataMap;
    dataMap["key1"] = "value1";
    dataMap["key2"] = "value2";

    string result = socket.MapToString(dataMap);
    
    EXPECT_EQ(result, "key1||value1$$key2||value2");
}

HWTEST_F(SpThreadSocketTest, MapToString_002, TestSize.Level1)
{
    SpThreadSocket socket;
    map<string, string> dataMap;
    dataMap["key1"] = "value1";

    string result = socket.MapToString(dataMap);
    
    EXPECT_EQ(result, "key1||value1");
}

HWTEST_F(SpThreadSocketTest, MapToString_003, TestSize.Level1)
{
    SpThreadSocket socket;
    map<string, string> dataMap;

    string result = socket.MapToString(dataMap);
    
    EXPECT_EQ(result, "");
}

HWTEST_F(SpThreadSocketTest, SplitMsg_001, TestSize.Level1)
{
    SpThreadSocket socket;
    string recvBuf = "init::param1 param2";

    string result = socket.SplitMsg(recvBuf);
    
    EXPECT_EQ(result, "param1 param2");
}

HWTEST_F(SpThreadSocketTest, SplitMsg_002, TestSize.Level1)
{
    SpThreadSocket socket;
    string recvBuf = "no_separator";

    string result = socket.SplitMsg(recvBuf);
    
    EXPECT_EQ(result, "no_separator");
}

HWTEST_F(SpThreadSocketTest, SplitMsg_003, TestSize.Level1)
{
    SpThreadSocket socket;
    string recvBuf = "";

    string result = socket.SplitMsg(recvBuf);
    
    EXPECT_EQ(result, "");
}

HWTEST_F(SpThreadSocketTest, SplitMsg_004, TestSize.Level1)
{
    SpThreadSocket socket;
    string recvBuf = "init::";

    string result = socket.SplitMsg(recvBuf);
    
    EXPECT_EQ(result, "");
}

HWTEST_F(SpThreadSocketTest, CheckTcpToken_001, TestSize.Level1)
{
    SpThreadSocket socket;
    SpServerSocket spSocket;
    string recvStr = "init::command -SESSIONID";
    string recvStrNoToken = "init::command";
    socket.SetToken("");

    SocketErrorType result = socket.CheckTcpToken(recvStr, spSocket, recvStrNoToken);
    
    EXPECT_EQ(result, SocketErrorType::OK);
}

HWTEST_F(SpThreadSocketTest, CheckTcpToken_002, TestSize.Level1)
{
    SpThreadSocket socket;
    SpServerSocket spSocket;
    string recvStr = "SP_daemon -editor";
    string recvStrNoToken = "SP_daemon -editor";
    socket.SetToken("");

    SocketErrorType result = socket.CheckTcpToken(recvStr, spSocket, recvStrNoToken);
    
    EXPECT_EQ(result, SocketErrorType::OK);
}

HWTEST_F(SpThreadSocketTest, CheckTcpToken_003, TestSize.Level1)
{
    SpThreadSocket socket;
    SpServerSocket spSocket;
    string recvStr = "init::command";
    string recvStrNoToken = "init::command";
    socket.SetToken("");

    SocketErrorType result = socket.CheckTcpToken(recvStr, spSocket, recvStrNoToken);
    
    EXPECT_EQ(result, SocketErrorType::TOKEN_CHECK_FAILED);
}

HWTEST_F(SpThreadSocketTest, CheckTcpToken_004, TestSize.Level1)
{
    SpThreadSocket socket;
    SpServerSocket spSocket;
    string recvStr = "init::command validtoken";
    string recvStrNoToken = "init::command";
    socket.SetToken("validtoken");

    SocketErrorType result = socket.CheckTcpToken(recvStr, spSocket, recvStrNoToken);
    
    EXPECT_EQ(result, SocketErrorType::OK);
}

HWTEST_F(SpThreadSocketTest, CheckTcpToken_005, TestSize.Level1)
{
    SpThreadSocket socket;
    SpServerSocket spSocket;
    string recvStr = "init::command wrongtoken";
    string recvStrNoToken = "init::command";
    socket.SetToken("validtoken");

    SocketErrorType result = socket.CheckTcpToken(recvStr, spSocket, recvStrNoToken);
    
    EXPECT_EQ(result, SocketErrorType::TOKEN_CHECK_FAILED);
}

HWTEST_F(SpThreadSocketTest, CheckUdpToken_001, TestSize.Level1)
{
    SpThreadSocket socket;
    socket.SetNeedUdpToken(false);

    SocketErrorType result = socket.CheckUdpToken("any:::command");
    
    EXPECT_EQ(result, SocketErrorType::OK);
}

HWTEST_F(SpThreadSocketTest, CheckUdpToken_002, TestSize.Level1)
{
    SpThreadSocket socket;
    socket.SetNeedUdpToken(true);

    SocketErrorType result = socket.CheckUdpToken("get_daemon_version");
    
    EXPECT_EQ(result, SocketErrorType::OK);
}

HWTEST_F(SpThreadSocketTest, CheckUdpToken_003, TestSize.Level1)
{
    SpThreadSocket socket;
    socket.SetNeedUdpToken(true);

    SocketErrorType result = socket.CheckUdpToken("set_pkgName::com.test.app");
    
    EXPECT_EQ(result, SocketErrorType::OK);
}

HWTEST_F(SpThreadSocketTest, CheckUdpToken_004, TestSize.Level1)
{
    SpThreadSocket socket;
    socket.SetNeedUdpToken(true);
    socket.SetToken("validtoken");

    SocketErrorType result = socket.CheckUdpToken("command:::validtoken");
    
    EXPECT_EQ(result, SocketErrorType::OK);
}

HWTEST_F(SpThreadSocketTest, CheckUdpToken_005, TestSize.Level1)
{
    SpThreadSocket socket;
    socket.SetNeedUdpToken(true);
    socket.SetToken("validtoken");

    SocketErrorType result = socket.CheckUdpToken("command:::wrongtoken");
    
    EXPECT_EQ(result, SocketErrorType::TOKEN_CHECK_FAILED);
}

HWTEST_F(SpThreadSocketTest, CheckUdpToken_006, TestSize.Level1)
{
    SpThreadSocket socket;
    socket.SetNeedUdpToken(true);

    SocketErrorType result = socket.CheckUdpToken("command");
    
    EXPECT_EQ(result, SocketErrorType::TOKEN_CHECK_FAILED);
}

HWTEST_F(SpThreadSocketTest, SocketErrorTypeToString_001, TestSize.Level1)
{
    SpThreadSocket socket;
    
    EXPECT_EQ(socket.SocketErrorTypeToString(SocketErrorType::OK), "OK");
    EXPECT_EQ(socket.SocketErrorTypeToString(SocketErrorType::TOKEN_CHECK_FAILED), "TOKEN_CHECK_FAILED");
    EXPECT_EQ(socket.SocketErrorTypeToString(SocketErrorType::INIT_FAILED), "INIT_FAILED");
    EXPECT_EQ(socket.SocketErrorTypeToString(SocketErrorType::START_FAILED), "START_FAILED");
    EXPECT_EQ(socket.SocketErrorTypeToString(SocketErrorType::STOP_FAILED), "STOP_FAILED");
    EXPECT_EQ(socket.SocketErrorTypeToString(SocketErrorType::START_RECORD_FAILED), "START_RECORD_FAILED");
    EXPECT_EQ(socket.SocketErrorTypeToString(SocketErrorType::STOP_RECORD_FAILED), "STOP_RECORD_FAILED");
}

HWTEST_F(SpThreadSocketTest, SocketErrorTypeToString_002, TestSize.Level1)
{
    SpThreadSocket socket;
    SocketErrorType invalidType = static_cast<SocketErrorType>(999);
    
    EXPECT_EQ(socket.SocketErrorTypeToString(invalidType), "UNKNOWN");
}

HWTEST_F(SpThreadSocketTest, SpGetPkg_001, TestSize.Level1)
{
    SpThreadSocket socket;
    string spMsg = "com.example.app$12345";

    string result = socket.SpGetPkg(spMsg);
    
    EXPECT_EQ(result, "com.example.app");
}

HWTEST_F(SpThreadSocketTest, SpGetPkg_002, TestSize.Level1)
{
    SpThreadSocket socket;
    string spMsg = "com.example.app";

    string result = socket.SpGetPkg(spMsg);
    
    EXPECT_EQ(result, "com.example.app");
}

HWTEST_F(SpThreadSocketTest, SpGetPkg_003, TestSize.Level1)
{
    SpThreadSocket socket;
    string spMsg = "";

    string result = socket.SpGetPkg(spMsg);
    
    EXPECT_EQ(result, "");
}

HWTEST_F(SpThreadSocketTest, SpGetPid_001, TestSize.Level1)
{
    SpThreadSocket socket;
    string spMsg = "com.example.app$12345";

    string result = socket.SpGetPid(spMsg);
    
    EXPECT_EQ(result, "12345");
}

HWTEST_F(SpThreadSocketTest, SpGetPid_002, TestSize.Level1)
{
    SpThreadSocket socket;
    string spMsg = "com.example.app";

    string result = socket.SpGetPid(spMsg);
    
    EXPECT_EQ(result, "");
}

HWTEST_F(SpThreadSocketTest, SpGetPid_003, TestSize.Level1)
{
    SpThreadSocket socket;
    string spMsg = "";

    string result = socket.SpGetPid(spMsg);
    
    EXPECT_EQ(result, "");
}

HWTEST_F(SpThreadSocketTest, IsPreset_001, TestSize.Level1)
{
    SpThreadSocket socket;
    
    EXPECT_TRUE(socket.IsPreset("app$pid"));
}

HWTEST_F(SpThreadSocketTest, IsPreset_002, TestSize.Level1)
{
    SpThreadSocket socket;
    
    EXPECT_FALSE(socket.IsPreset("app"));
}

HWTEST_F(SpThreadSocketTest, SetToken_GetToken_001, TestSize.Level1)
{
    SpThreadSocket socket;
    string token = "test_token_12345";

    socket.SetToken(token);
    string result = socket.GetToken();
    
    EXPECT_EQ(result, token);
}

HWTEST_F(SpThreadSocketTest, SetToken_GetToken_002, TestSize.Level1)
{
    SpThreadSocket socket;
    string emptyToken = "";

    socket.SetToken(emptyToken);
    string result = socket.GetToken();
    
    EXPECT_EQ(result, "");
}

HWTEST_F(SpThreadSocketTest, SetNeedUdpToken_001, TestSize.Level1)
{
    SpThreadSocket socket;
    socket.SetNeedUdpToken(true);
    
    SocketErrorType result = socket.CheckUdpToken("command:::token");
    EXPECT_EQ(result, SocketErrorType::TOKEN_CHECK_FAILED);
}

HWTEST_F(SpThreadSocketTest, SetNeedUdpToken_002, TestSize.Level1)
{
    SpThreadSocket socket;
    socket.SetNeedUdpToken(false);
    
    SocketErrorType result = socket.CheckUdpToken("command");
    EXPECT_EQ(result, SocketErrorType::OK);
}

HWTEST_F(SpThreadSocketTest, split_001, TestSize.Level1)
{
    SpThreadSocket socket;
    string str = "a,b,c,d";
    string delimiter = ",";

    vector<string> result = socket.split(str, delimiter);
    
    EXPECT_EQ(result.size(), 4);
    EXPECT_EQ(result[0], "a");
    EXPECT_EQ(result[1], "b");
    EXPECT_EQ(result[2], "c");
    EXPECT_EQ(result[3], "d");
}

HWTEST_F(SpThreadSocketTest, split_002, TestSize.Level1)
{
    SpThreadSocket socket;
    string str = "single";
    string delimiter = ",";

    vector<string> result = socket.split(str, delimiter);
    
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "single");
}

HWTEST_F(SpThreadSocketTest, split_003, TestSize.Level1)
{
    SpThreadSocket socket;
    string str = "";
    string delimiter = ",";

    vector<string> result = socket.split(str, delimiter);
    
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "");
}

HWTEST_F(SpThreadSocketTest, split_004, TestSize.Level1)
{
    SpThreadSocket socket;
    string str = "a,b,c,";
    string delimiter = ",";

    vector<string> result = socket.split(str, delimiter);
    
    EXPECT_EQ(result.size(), 4);
    EXPECT_EQ(result[3], "");
}

HWTEST_F(SpThreadSocketTest, RemoveToken_001, TestSize.Level1)
{
    SpThreadSocket socket;
    string recvMessage = "init::command:::token123";

    socket.RemoveToken(recvMessage);
    
    EXPECT_EQ(recvMessage, "init::command");
}

HWTEST_F(SpThreadSocketTest, RemoveToken_002, TestSize.Level1)
{
    SpThreadSocket socket;
    string recvMessage = "init::command";

    socket.RemoveToken(recvMessage);
    
    EXPECT_EQ(recvMessage, "init::command");
}

HWTEST_F(SpThreadSocketTest, GetTime_001, TestSize.Level1)
{
    SpThreadSocket socket;
    string recvBuf = "***100";

    string result = socket.GetTime(recvBuf);
    
    EXPECT_EQ(result, "");
}

HWTEST_F(SpThreadSocketTest, GetTime_002, TestSize.Level1)
{
    SpThreadSocket socket;
    string recvBuf = "init::command***200";

    string result = socket.GetTime(recvBuf);
    
    EXPECT_EQ(result, "init::command");
}

HWTEST_F(SpThreadSocketTest, GetTime_003, TestSize.Level1)
{
    SpThreadSocket socket;
    string recvBuf = "command";

    string result = socket.GetTime(recvBuf);
    
    EXPECT_EQ(result, "command");
}

HWTEST_F(SpThreadSocketTest, SocketHeartbeat_001, TestSize.Level1)
{
    SpThreadSocket socket;
    
    socket.SocketHeartbeat();
    
    SUCCEED();
}
}
}
