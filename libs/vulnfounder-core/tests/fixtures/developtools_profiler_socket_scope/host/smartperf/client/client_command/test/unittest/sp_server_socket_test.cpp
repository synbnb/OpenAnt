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
#include <memory>
#include <iostream>
#include <sstream>
#include <thread>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "unistd.h"
#include "sp_utils.h"
#include "sp_server_socket.h"
#include "common.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class SpServerSocketTest : public testing::Test {
public:
    int sock = 0;
    struct sockaddr_in servAddr;

    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(SpServerSocketTest, InitTcpTest, TestSize.Level1)
{
    std::string spDaemon = "SP_daemon";
    std::string result;
    bool tcpRet;
    SPUtils::LoadCmd(spDaemon, result);
    int tcpPort = 8284;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error";
        return;
    }
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(tcpPort);
    if (inet_pton(AF_INET, "127.0.0.1", &servAddr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported";
        return;
    }
    if (connect(sock, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
        std::cerr << "Connection Failed";
        return;
    }
    std::string message = "startRecord::";
    char buffer[1024] = {0};
    send(sock, message.c_str(), strlen(message.c_str()), 0);
    read(sock, buffer, 1024);
    std::string tcpBuffer(buffer);
    if (tcpBuffer.find("startRecord") != std::string::npos) {
        tcpRet = true;
    }
    EXPECT_TRUE(tcpRet);
    close(sock);
}

HWTEST_F(SpServerSocketTest, AcceptTest, TestSize.Level0)
{
    SpServerSocket serverSocket;
    int connFd = serverSocket.Accept();
    EXPECT_EQ(connFd, -1);
}

HWTEST_F(SpServerSocketTest, SendtoTest, TestSize.Level0)
{
    SpServerSocket serverSocket;
    std::string sendBuf = "test";
    int ret = serverSocket.Sendto(sendBuf);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(SpServerSocketTest, RecvFailureTest, TestSize.Level0)
{
    SpServerSocket serverSocket;
    int result = serverSocket.Recv();
    ASSERT_LT(result, 0);
}

HWTEST_F(SpServerSocketTest, RecvBufTest, TestSize.Level0)
{
    SpServerSocket serverSocket;
    std::string rbuf = serverSocket.RecvBuf();
    EXPECT_EQ(rbuf, "");
}
}
}