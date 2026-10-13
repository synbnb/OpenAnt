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
#include <exception>
#include <iostream>
#include <string>
#include <thread>
#include <gtest/gtest.h>
#include <unistd.h>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <chrono>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "sdk_data_recv.h"
#include "sp_task.h"
#include "GetLog.h"
const int TCP_PORT = 20888;
using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class SPdaemonGetLogTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}

    int CreateAndBindSocket()
    {
        int tcpServerFd = socket(AF_INET, SOCK_STREAM, 0);
        if (tcpServerFd < 0) {
            perror("TCP socket creation failed");
            return -1;
        }

        struct sockaddr_in tcpServerAddr = {};
        tcpServerAddr.sin_family = AF_INET;
        tcpServerAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
        tcpServerAddr.sin_port = htons(TCP_PORT);

        if (::bind(tcpServerFd, reinterpret_cast<struct sockaddr*>(&tcpServerAddr), sizeof(tcpServerAddr)) < 0) {
            perror("TCP bind failed");
            close(tcpServerFd);
            return -1;
        }

        return tcpServerFd;
    }

    int AcceptClientConnection(int tcpServerFd)
    {
        if (listen(tcpServerFd, 1) < 0) {
            perror("Listen failed");
            return -1;
        }

        int clientFd = accept(tcpServerFd, nullptr, nullptr);
        if (clientFd < 0) {
            perror("Accept failed");
        }
        return clientFd;
    }

    void GetLogCommand()
    {
        int tcpServerFd = CreateAndBindSocket();
        if (tcpServerFd < 0) {
            return;
        }

        int clientFd = AcceptClientConnection(tcpServerFd);
        if (clientFd < 0) {
            close(tcpServerFd);
            return;
        }

        FILE* fp = fopen("/data/local/tmp/getlogtest.tar.gz", "wb");
        if (!fp) {
            perror("File open failed");
            close(clientFd);
            close(tcpServerFd);
            return;
        }
        char buffer[4096];
        ssize_t bytesRead;
        while ((bytesRead = recv(clientFd, buffer, sizeof(buffer), 0)) > 0) {
            if (fwrite(buffer, 1, bytesRead, fp) != bytesRead) {
                perror("fwrite failed");
                close(clientFd);
                close(tcpServerFd);
                return;
            }
        }
        int fcloseResult = fclose(fp);
        if (fcloseResult == EOF) {
            perror("fclose failed");
            close(tcpServerFd);
            return;
        }

        close(clientFd);
        close(tcpServerFd);
    }
};

/**
 * @tc.name: GetLog::SendFileTestCase
 * @tc.desc: Test SendFileTestCase
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonGetLogTest, SendFileTestCase, TestSize.Level1)
{
    std::map<std::string, std::string> result = GetLog::GetInstance().ItemData();
    std::thread tcpServer = std::thread([this]() {
        GetLogCommand();
    });
    GetLog::GetInstance().SetLogFileSocketPort(TCP_PORT);
    GetLog::GetInstance().LogFileSocketConnect();
    GetLog::GetInstance().SendLogFile();
    tcpServer.join();
}
} // namespace SmartPerf
}