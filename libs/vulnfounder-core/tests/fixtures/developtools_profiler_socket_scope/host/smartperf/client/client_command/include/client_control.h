/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
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
#ifndef CLIENTCONTROL_H
#define CLIENTCONTROL_H
#include <iostream>
#include <netinet/in.h>
namespace OHOS {
namespace SmartPerf {
class ClientControl {
public:
    int SocketStart(const std::string &args);
    int SocketStop();
    int InitSocket();
    void StartSPDaemon() const;
    int CloseSocket();

private:
    int clientSocket = 0;
    struct sockaddr_in serverAddress;
    static const int arraySize = 1024;
    char buffer[arraySize] = {0};
    int protNumber = 8284;
    std::string message = "init:::-SESSIONID 1 -INTERVAL 1000 ";
    const char *message1 = "start:::";
    const char *message2 = "stop::";
    int numBuff = 1024;
};
}
}
#endif