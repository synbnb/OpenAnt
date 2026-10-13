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
#ifndef SP_SERVERSOCKET_H
#define SP_SERVERSOCKET_H
#include <iostream>
#include <netinet/in.h>
namespace OHOS {
namespace SmartPerf {
enum class ProtoType {
    TCP,
    UDP,
    UDPEX
};
class SpServerSocket {
public:
    SpServerSocket();
    ~SpServerSocket();
    // 创建一个套接字
    int Init(ProtoType type);
    // UDP
    int Sendto(const std::string &sendBuf);
    int Recvfrom();
    // TCP
    int Accept();
    int Send(const std::string &sendBuf) const;
    int Recv();
    // 关闭
    void Close();
    std::string RecvBuf() const;

private:
    int sock = -1;
    struct sockaddr_in local;
    struct sockaddr_in client;
    int sockPort;
    int connFd = -1;
    const int listenCount = 5;
    const static int buffSizeRecv = 1024;
    char rbuf[buffSizeRecv] = "";
    const int udpPort = 8283;
    const int tcpPort = 8284;
    const int udpExPort = 8285;
};
}
}

#endif // !SPSERVERSOCKET