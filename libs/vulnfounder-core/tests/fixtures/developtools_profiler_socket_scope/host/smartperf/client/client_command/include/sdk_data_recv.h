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
#ifndef SDK_DATA_RECV_H
#define SDK_DATA_RECV_H
#include <pthread.h>
#include <vector>
#include <string>
#include <arpa/inet.h>
#include "sp_profiler.h"
#include "sp_data.h"
#include <sys/select.h>
#include <thread>

namespace OHOS {
    namespace SmartPerf {
#define OH_DATA_PORT 12567
#define OH_DATA_PORT_TRY_NUM 3
#define MSG_MAX_LEN 256
#define PARA_NAME_MAX_LEN 16
#define SOCKET_PORT_NUM_PER_TYPE 10
#define OH_SOCKET_MAX 10

        typedef struct {
            char name[PARA_NAME_MAX_LEN];
            int isEvent;
            int value;
        } ParaStatus;

        struct ServerParams {
            time_t startTime;
            int serverFd;
            int pipFd[2];
            int receiveFd[OH_SOCKET_MAX];
        };
        class SdkDataRecv : public SpProfiler {
        public:
            std::map<std::string, std::string> ItemData() override;
            void StartExecutionOnce(bool isPause) override;
            void FinishtExecutionOnce(bool isPause) override;
            static SdkDataRecv &GetInstance()
            {
                static SdkDataRecv instance;
                return instance;
            }
            static int CreateOhSocketServer(int basePort);
            std::string OhDataReceive(int index, ServerParams &params);
            std::string ProcessData(std::string& message, ServerParams &params);
            void ServerThread();

            void RunServerThread(ServerParams &params);
            void HandleReceiveFd(int i, ServerParams &params);
            void HandleServerFd(ServerParams &params);
            void SetUpFdSet(ServerParams &params);
            void CleanUpResources(ServerParams &params);
            void GetSdkDataRealtimeData(std::map<std::string, std::string> &dataMap);
            void SocketCommandVerification(std::string &resStr, ServerParams &params);
            void GetSdkFpsAndSystime(const std::string &sdkStr);
            std::string GetSdkFps() const;
            std::string GetSdkSystime() const;
            void SetFilePath(const std::string& path);

            std::vector<std::string> sdkVec_;
        private:
            SdkDataRecv();
            SdkDataRecv(const SdkDataRecv &);
            SdkDataRecv &operator = (const SdkDataRecv &);
            int listenFd = -1;
            int sendSocket = -1;
            std::string userTpye = "";
            bool collectRunring  = false;
            int maxFd = 0;
            fd_set readFds;
            std::string receiveBuffer = "";
            std::string sdkDataRealtimeData = "";
            ServerParams sdkParams;
            std::mutex realtimeDataLock;
            std::string sdkFps;
            std::string sdkSystime;
            std::thread th_;
            std::string filePath_;
        };
    }
}
#endif