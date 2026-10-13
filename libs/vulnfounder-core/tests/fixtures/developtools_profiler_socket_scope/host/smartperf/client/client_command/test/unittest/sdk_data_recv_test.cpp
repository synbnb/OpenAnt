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
#include "sdk_data_recv.h"
#include "sp_task.h"
const int TCP_PORT = 12567;
using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class SPdaemonSdkDataTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
    int ConnectSdkServer()
    {
        struct sockaddr_in servaddr;
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("socket creation failed");
            return -1;
        }

        std::fill_n(reinterpret_cast<char*>(&servaddr), sizeof(servaddr), 0);
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
        servaddr.sin_port = htons(TCP_PORT);
        if (::bind(sockfd, reinterpret_cast<struct sockaddr *>(&servaddr), sizeof(servaddr)) < 0) {
            printf("Init Socket Bind failed prot(%d)", TCP_PORT);
            return -1;
        }

        if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
            printf("connect failed: %s", strerror(errno));
            close(sockfd);
            return -1;
        }
        return sockfd;
    }
};

/**
 * @tc.name: SdkDataRecv::ItemData
 * @tc.desc: Test ItemData
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonSdkDataTest, ItemDataTestCase, TestSize.Level1)
{
    std::map<std::string, std::string> result = SdkDataRecv::GetInstance().ItemData();
    EXPECT_EQ(result.size(), 0);
}
/**
 * @tc.name: SdkDataRecv::ServerThread
 * @tc.desc: Test ServerThread
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonSdkDataTest, ServerThreadTestCase, TestSize.Level1)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    int sockfd = ConnectSdkServer();
    EXPECT_NE(sockfd, -1);
    std::string sendData = "{src:test,para0:1,time:1000,enable:1,value:1}";
    int ret = send(sockfd, sendData.c_str(), sendData.size(), 0);
    if (ret != sendData.size()) {
        printf("Send message error: %d, %s\n", sockfd, strerror(errno));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    close(sockfd);
    EXPECT_EQ(SdkDataRecv::GetInstance().sdkVec_.size(), 0);
}
}
}