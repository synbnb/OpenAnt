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
#include <sstream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "include/sp_server_socket.h"
#include "include/sp_log.h"
namespace OHOS {
namespace SmartPerf {
SpServerSocket::SpServerSocket() : local{0}, client{}, sockPort(0)
{
}

SpServerSocket::~SpServerSocket()
{
    Close();
}

int SpServerSocket::Init(ProtoType type)
{
    if (type == ProtoType::TCP) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        sockPort = tcpPort;
    }
    if (type == ProtoType::UDP || type == ProtoType::UDPEX) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        sockPort = (type == ProtoType::UDP ? udpPort : udpExPort);
    }
    if (sock < 0) {
        LOGE("SpServerSocket::Init Socket Create Failed");
        return -1;
    }
    if (type == ProtoType::TCP) {
        int optval = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
            LOGE("SpServerSocket::Init Socket Setsockopt failed prot(%d)", sockPort);
            return -1;
        }
    }
    local.sin_family = AF_INET;
    local.sin_port = htons(sockPort);
    local.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (::bind(sock, reinterpret_cast<struct sockaddr *>(&local), sizeof(local)) < 0) {
        LOGE("SpServerSocket::Init Socket Bind failed prot(%d)", sockPort);
        return -1;
    }
    if (type == ProtoType::TCP) {
        if (listen(sock, listenCount) < 0) {
            LOGE("SpServerSocket::Init Socket Listen failed");
            return -1;
        }
    }

    LOGD("SpServerSocket::Init OK,prot(%d)", sockPort);
    return 0;
}

int SpServerSocket::Accept()
{
    connFd = accept(sock, nullptr, nullptr);
    return connFd;
}

int SpServerSocket::Sendto(const std::string &sendBuf)
{
    LOGD("SpServerSocket Sendto sendBuf(%s)", sendBuf.c_str());
    socklen_t len = sizeof(sockaddr_in);
    sendto(sock, sendBuf.c_str(), sendBuf.size(), 0, reinterpret_cast<struct sockaddr *>(&client), len);
    return 0;
}

int SpServerSocket::Send(const std::string &sendBuf) const
{
    int sendBytes = send(connFd, sendBuf.c_str(), sendBuf.size(), 0);
    if (sendBytes < 0) {
        LOGE("SpServerSocket::Send Error(%d) fd(%d)", sendBytes, connFd);
        return -1;
    }
    return 0;
}

void SpServerSocket::Close()
{
    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    local.sin_family = AF_INET;
    local.sin_port = htons(sockPort);
    local.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (::bind(sock, reinterpret_cast<struct sockaddr *>(&local), sizeof(local)) < 0) {
        LOGE("SpServerSocket::Init Socket Bind failed");
    }
}

int SpServerSocket::Recvfrom()
{
    bzero(rbuf, sizeof(rbuf));
    socklen_t len = sizeof(sockaddr_in);
    int l = recvfrom(sock, rbuf, sizeof(rbuf) - 1, 0, reinterpret_cast<struct sockaddr *>(&client), &len);
    if (l > 0) {
        std::cout << "Client:" << rbuf << std::endl;
    } else {
        LOGE("SpServerSocket::Recvfrom Error(%d)", l);
        return -1;
    }
    return l;
}

int SpServerSocket::Recv()
{
    bzero(rbuf, sizeof(rbuf));
    int l = recv(connFd, rbuf, sizeof(rbuf) - 1, 0);
    if (l > 0) {
        std::cout << "Client:" << rbuf << std::endl;
    } else {
        LOGE("SpServerSocket::recv Error(%d) fd(%d)", l, connFd);
        return -1;
    }
    return l;
}

std::string SpServerSocket::RecvBuf() const
{
    std::string recvBuf = rbuf;
    return recvBuf;
}

}
}
