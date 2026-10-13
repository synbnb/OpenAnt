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
#include <fstream>
#include <climits>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <iostream>
#include <thread>
#include <unistd.h>
#include <string>
#include <regex>
#include <cstdarg>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/in.h>
#include "include/sp_utils.h"
#include "include/startup_delay.h"
#include "include/sp_log.h"
#include "include/sdk_data_recv.h"
#include "memory_collector.h"
#include "collect_result.h"
#include "include/sp_task.h"
#include "include/sp_utils.h"
#include "securec.h"
namespace OHOS {
    namespace SmartPerf {
        SdkDataRecv::SdkDataRecv()
        {
            FD_ZERO(&readFds);
        }

        std::map<std::string, std::string> SdkDataRecv::ItemData()
        {
            std::map<std::string, std::string> ret;
            GetSdkDataRealtimeData(ret);
            LOGI("SdkDataRecv:ItemData map size(%u)", ret.size());
            return ret;
        }

        void SdkDataRecv::StartExecutionOnce(bool isPause)
        {
            if (!isPause) {
                sdkParams.startTime = SPUtils::GetCurTime();
            }
            OHOS::system::SetParameter("debug.smartperf.sdkdataenable", "1");
            collectRunring = true;
            WLOGI("Starting sdkdata collection in new thread");
            if (th_.joinable()) {
                th_.join();
            }
            th_ = std::thread([this]() { ServerThread(); });
        }

        void SdkDataRecv::FinishtExecutionOnce(bool isPause)
        {
            WLOGI("Disabling sdk data collection and resetting parameters");
            OHOS::system::SetParameter("debug.smartperf.sdkdataenable", "0");
            collectRunring = false;
            if (listenFd != -1) {
                LOGD("Closing sdk data listenFd: %d", listenFd);
                close(listenFd);
                listenFd = -1;
            }

            if (th_.joinable()) {
                th_.join();
            }
            if (isPause) {
                return;
            }

            if (sdkVec_.empty()) {
                WLOGI("SDK data is not enabled or sdkvec is empty");
                return;
            }

            LOGD("SDK data stop");
            char outSdkDataDirChar[PATH_MAX] = {0x00};
            if (realpath(filePath_.c_str(), outSdkDataDirChar) == nullptr) {
                WLOGE("data dir %s is nullptr", filePath_.c_str());
                return;
            }
            const std::string outSdkDataPath = std::string(outSdkDataDirChar) + "/sdk_data.csv";
            std::ofstream outFile(outSdkDataPath.c_str(), std::ios::out | std::ios::trunc);
            if (!outFile.is_open()) {
                WLOGE("data %s open failed", outSdkDataPath.c_str());
                return;
            }
            std::string title = "source,timestamp,eventName,enable,value\r";
            outFile << title << std::endl;
            for (const auto &item : sdkVec_) {
                outFile << item << std::endl;
            }
            outFile.close();
            WLOGI("SDK data written successfully to %s", outSdkDataPath.c_str());
        }

        int SdkDataRecv::CreateOhSocketServer(int basePort)
        {
            int i = 0;
            int socketFd = 0;
            struct sockaddr_in address;
            const int reuse = 1;

            LOGD("Creating socket server on base port: %d", basePort);

            socketFd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
            if (socketFd < 0) {
                LOGE("Failed to create socket. Error: %d", errno);
                return -1;
            }
            setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

            std::fill_n(reinterpret_cast<char*>(&address), sizeof(address), 0);
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = inet_addr("127.0.0.1");

            for (i = 0; i < SOCKET_PORT_NUM_PER_TYPE; i++) {
                address.sin_port = htons(basePort + i);
                if (::bind(socketFd, reinterpret_cast<struct sockaddr *>(&address), sizeof(address)) == 0) {
                    LOGD("Socket bound successfully to port: %d", basePort + i);
                    break;
                }
            }

            if (i >= SOCKET_PORT_NUM_PER_TYPE) {
                LOGE("Failed to bind socket after trying all ports starting from: %d", basePort);
                return -1;
            }

            if (listen(socketFd, OH_SOCKET_MAX) < 0) {
                close(socketFd);
                LOGE("Failed to listen on socket. Error: %d", errno);
                return -1;
            }

            LOGD("Listening on port %d, socket fd: %d", basePort + i, socketFd);
            return socketFd;
        }
        std::string SdkDataRecv::ProcessData(std::string& message, ServerParams &params)
        {
            std::stringstream ss(message);
            std::string enable;
            std::string eventName;
            std::string gameHead;
            std::string item;
            std::string realTimestamp;
            std::string source;
            std::string systime;
            std::string smartFpsName;
            std::string timestamp;
            std::string value;
            while (std::getline(ss, item, ',')) {
                std::stringstream itemSS(item);
                std::string first;
                std::string second;
                std::getline(itemSS, first, ':');
                std::getline(itemSS, second, ':');
                if (first == "src") {
                    source = second;
                } else if (first == "para0") {
                    eventName = second;
                    if (second == "SmartFps") {
                        smartFpsName = second;
                    }
                } else if (first == "time") {
                    realTimestamp = std::to_string(SPUtilesTye::StringToSometype<long long>(second) -
                        sdkParams.startTime);
                    timestamp = std::to_string(SPUtilesTye::StringToSometype<long long>(second) - params.startTime);
                } else if (first == "enable") {
                    enable = second;
                } else if (first == "value") {
                    value = second;
                } else if (first == "systime") {
                    systime = second;
                }
            }
            item = source + "," + timestamp + "," + eventName + "," + enable + "," + value + "\r\n";
            gameHead = source + "," + timestamp + "," + smartFpsName + "," + enable +
                "," + value + "," + systime + "\r\n";
            GetSdkFpsAndSystime(gameHead);
            std::unique_lock<std::mutex> lock(realtimeDataLock);
            sdkDataRealtimeData += source + "_" + realTimestamp + "_" + eventName + "_" + enable + "_" + value + ";";
            return item;
        }

        std::string SdkDataRecv::OhDataReceive(int index, ServerParams &params)
        {
            char receiveBuf[MSG_MAX_LEN];
            std::string resStr;
            int readLen = 0;
            if ((readLen = read(params.receiveFd[index], receiveBuf, MSG_MAX_LEN)) <= 0) {
                close(params.receiveFd[index]);
                params.receiveFd[index] = -1;
                LOGE("Failed to read data from socket fd[%d]. Read length: %d, Error: %d", index, readLen, errno);
                return "";
            }
            if (readLen < MSG_MAX_LEN) {
                receiveBuf[readLen] = '\0';
            } else {
                receiveBuf[MSG_MAX_LEN - 1] = '\0';
            }
            receiveBuffer = receiveBuf;
            SocketCommandVerification(resStr, params);

            if (!resStr.empty() && resStr.back() == '\n') {
                resStr.pop_back();
            }
            return resStr;
        }

        void SdkDataRecv::ServerThread()
        {
            for (int i = 0; i < OH_SOCKET_MAX; i++) {
                sdkParams.receiveFd[i] = -1;
            }
            sdkParams.startTime = SPUtils::GetCurTime();
            sdkParams.serverFd = CreateOhSocketServer(OH_DATA_PORT);
            if (sdkParams.serverFd < 0) {
                LOGE("Failed to create sdk data server, exiting...");
                return;
            }

            if (pipe(sdkParams.pipFd) == -1) {
                LOGE("Failed to create sdk data pipe.");
                close(sdkParams.serverFd);
                return;
            }
            listenFd = sdkParams.pipFd[1];
            RunServerThread(sdkParams);
            LOGD("Sdk Data server thread exit.");
        }

        void SdkDataRecv::RunServerThread(ServerParams &params)
        {
            while (collectRunring) {
                SetUpFdSet(params);
                if (select(maxFd + 1, &readFds, nullptr, nullptr, nullptr) <= 0) {
                    continue;
                }
                for (int i = 0; i < OH_SOCKET_MAX; i++) {
                    HandleReceiveFd(i, params);
                }
                HandleServerFd(params);
            }
            CleanUpResources(params);
        }

        void SdkDataRecv::SetUpFdSet(ServerParams &params)
        {
            FD_ZERO(&readFds);
            FD_SET(params.serverFd, &readFds);
            FD_SET(params.pipFd[0], &readFds);

            maxFd = std::max(params.serverFd, params.pipFd[0]);
            for (int i = 0; i < OH_SOCKET_MAX; i++) {
                if (params.receiveFd[i] >= 0) {
                    FD_SET(params.receiveFd[i], &readFds);
                    maxFd = std::max(maxFd, params.receiveFd[i]);
                    LOGD("Sdk data adding receiveFd[%d]: %d to FD set", i, params.receiveFd[i]);
                }
            }
        }

        void SdkDataRecv::HandleReceiveFd(int i, ServerParams &params)
        {
            if (params.receiveFd[i] >= 0 && FD_ISSET(params.receiveFd[i], &readFds)) {
                std::string data = OhDataReceive(i, params);
                if (SPTask::GetInstance().GetRecordState()) {
                    sdkVec_.push_back(data);
                }
            }
        }

        void SdkDataRecv::HandleServerFd(ServerParams &params)
        {
            if (!FD_ISSET(params.serverFd, &readFds)) {
                return;
            }

            int fd = accept(params.serverFd, nullptr, nullptr);
            if (fd < 0) {
                return;
            }

            for (int i = 0; i < OH_SOCKET_MAX; i++) {
                if (params.receiveFd[i] < 0) {
                    params.receiveFd[i] = fd;
                    if (fd > maxFd) {
                        maxFd = fd;
                    }
                    break;
                }
            }
        }

        void SdkDataRecv::CleanUpResources(ServerParams &params)
        {
            if (params.serverFd != -1) {
                LOGD("Closing sdk data server socket fd: %d", params.serverFd);
                close(params.serverFd);
                params.serverFd = -1;
            }
            if (params.pipFd[0] != -1) {
                close(params.pipFd[0]);
                params.pipFd[0] = -1;
            }
            for (int i = 0; i < OH_SOCKET_MAX; i++) {
                if (params.receiveFd[i] != -1) {
                    close(params.receiveFd[i]);
                    params.receiveFd[i] = -1;
                }
            }
        }

        void SdkDataRecv::GetSdkDataRealtimeData(std::map<std::string, std::string> &dataMap)
        {
            std::unique_lock<std::mutex> lock(realtimeDataLock);
            if (sdkDataRealtimeData.size() > 0) {
                dataMap.insert({"sdkData", sdkDataRealtimeData});
                sdkDataRealtimeData.clear();
            }
        }

        void SdkDataRecv::SocketCommandVerification(std::string &resStr, ServerParams &params)
        {
            bool processFlag = true;
            while (processFlag) {
                size_t start = receiveBuffer.find('{');
                if (start == std::string::npos) {
                    processFlag = false;
                    break;
                }

                size_t end = receiveBuffer.find('}', start);
                if (end == std::string::npos) {
                    processFlag = false;
                    break;
                }

                std::size_t startPosition = start + 1;
                std::size_t length = end > start ? end - start - 1 : 0;
                if (startPosition >= receiveBuffer.size() || length > receiveBuffer.size() - startPosition) {
                    processFlag = false;
                    break;
                }

                std::string message = receiveBuffer.substr(startPosition, length);
                resStr += ProcessData(message, params);

                receiveBuffer.erase(0, end + 1);
                const int bufferSizeCheck = 2;
                if (receiveBuffer.size() <= bufferSizeCheck) {
                    processFlag = false;
                }
            }
        }

        void SdkDataRecv::GetSdkFpsAndSystime(const std::string &sdkStr)
        {
            std::stringstream ss(sdkStr);
            std::string filed;
            std::string curvalue;
            std::string cursystem;
            int indexFour = 4;
            int indexFive = 5;
            std::vector<std::string> vec;
            size_t endPos = sdkStr.find("\r\n");
            if (endPos != std::string::npos) {
                ss = std::stringstream(sdkStr.substr(0, endPos));
            }

            while (getline(ss, filed, ',')) {
                vec.push_back(filed);
            }
            for (size_t i = 0; i < vec.size(); i++) {
                curvalue = vec[indexFour];
                cursystem = vec[indexFive];
                if (curvalue != "0" && cursystem != "0") {
                    sdkFps = curvalue;
                    sdkSystime = cursystem;
                }
            }
        }

        std::string SdkDataRecv::GetSdkFps() const
        {
            return sdkFps;
        }

        std::string SdkDataRecv::GetSdkSystime() const
        {
            return sdkSystime;
        }

        void SdkDataRecv::SetFilePath(const std::string& path)
        {
            filePath_ = path;
        }
    }
}