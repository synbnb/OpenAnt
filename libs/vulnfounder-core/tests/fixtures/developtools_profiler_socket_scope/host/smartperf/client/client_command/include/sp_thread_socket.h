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
#ifndef SP_THREAD_SOCKET_H
#define SP_THREAD_SOCKET_H
#include "sp_server_socket.h"
#include "sp_task.h"
#include "ByTrace.h"
#include <thread>
#include "GpuCounter.h"
namespace OHOS {
namespace SmartPerf {
enum class SocketConnectType {
    CMD_SOCKET,
    EDITOR_SOCKET,
};

enum class SocketErrorType {
    OK,
    TOKEN_CHECK_FAILED,
    INIT_FAILED,
    START_FAILED,
    STOP_FAILED,
    START_RECORD_FAILED,
    STOP_RECORD_FAILED,
};
class SpThreadSocket {
public:
    static SpThreadSocket &GetInstance()
    {
        static SpThreadSocket instance;
        return instance;
    }

    std::string MapToString(std::map<std::string, std::string>& dataMap) const;
    std::string SplitMsg(const std::string &recvBuf) const;
    void Process(ProtoType type);
    SocketErrorType CheckTcpToken(const std::string& recvStr, SpServerSocket &spSocket,
        const std::string& recvStrNoToken) const;
    SocketErrorType CheckUdpToken(const std::string& recvStr) const;
    void TypeTcp(SpServerSocket &spSocket);
    void InitRecv(const std::string& recvStr, SpServerSocket &spSocket, SocketConnectType type) const;
    void StartRecv(SpServerSocket &spSocket);
    void StartRecvRealtime(SpServerSocket &spSocket) const;
    void StopRecvRealtime(SpServerSocket &spSocket);
    void StartRecvRecord(SpServerSocket &spSocket) const;
    void StopRecvRecord(SpServerSocket &spSocket) const;
    void SendTokenFailedMessage(SpServerSocket &socket, const std::string &message) const;
    void DealMsg(const std::string& recvStr, SpServerSocket &spSocket, SocketErrorType tokenStatus);
    void EditorRecv(const std::string& recvStr, const SpServerSocket &spSocket) const;
    void BackDesktop() const;
    void HandleMsg(SpServerSocket &spSocket);
    void HeartbeatDetection(const std::string& recvBuf);
    void UdpStartInitFunc(const std::string& recvBuf, SpServerSocket &spSocket);
    void GetCatchTraceResult(std::string& retCode, SpServerSocket &spSocket,
        std::unordered_map<MessageType, std::string>::const_iterator iterator, const std::string& recvBuf);
    void HandleUDPMsg(SpServerSocket &spSocket, std::map<std::string, std::string>& data, std::string& retCode,
        std::unordered_map<MessageType, std::string>::const_iterator iterator);
    void SocketHeartbeat() const;
    void FetchCpuStats(SpServerSocket &spSocket, std::map<std::string, std::string>& data) const;
    void HandleNullMsg(SpServerSocket &spSocket, SpProfiler *profiler, std::string& retCode,
        const std::string& recvBuf, std::unordered_map<MessageType, std::string>::const_iterator iterator);
    std::string GetTime(std::string &recvBuf);
    void GetTraceStartPoint(std::string &recvBuf);
    std::vector<std::string> split(const std::string &str, const std::string &delimiter);
    void HandleNullAddMsg(SpServerSocket &spSocket, SpProfiler *profiler, std::string& retCode,
        const std::string& recvBuf, std::unordered_map<MessageType, std::string>::const_iterator iterator);
    void UdpStartMessProcess(SpServerSocket &spSocket, SpProfiler *profiler, std::string& retCode,
        const std::string& recvBuf, std::unordered_map<MessageType, std::string>::const_iterator iterator);
    std::string SocketErrorTypeToString(SocketErrorType errorType) const;
    void GetSocketPort(const std::string& buffer);
    void ResetValue(std::string retCode) const;
    void GetProcessIdByPkgName(std::unordered_map<MessageType, std::string>::const_iterator iterator);
    std::string SpGetPkg(const std::string &spMsg) const;
    std::string SpGetPid(const std::string &spMsg) const;
    bool IsPreset(const std::string &spMsg) const;
    void SetToken(const std::string& token);
    std::string GetToken() const;
    void SetNeedUdpToken(bool isNeed);
    void ConnectAndSendFile(SpServerSocket &spSocket, const std::string filePath);
    int FileSocketConnect();
    int SendFile(const std::string& filePath);
    void StartHapCollecting(SpServerSocket &spSocket);
    void RemoveToken(std::string &recvMessage);
    void HandleMsgTrace(std::string& recvMessage);
    void SendTraceFile(const std::string& recvBuf, SpServerSocket &spSocket);
private:
    bool flagRunning = false;
    bool socketConnect = true;
    std::string checkToken = "";    // 拉起测试时校验
    bool isNeedUdpToken = true;     // 如果是hdc shell拉起，不需要校验token以兼容旧版本
    GpuCounter &gpuCounter = GpuCounter::GetInstance();
    const std::string traceOriginPath = "/data/log/hitrace/";
    const std::string sysTracePath = "/data/local/tmp/";
    const std::string traceDir = "/data/local/tmp/smartperfHitrace/";
    const std::string indexFilePath = "/data/local/tmp/smartperf/1/t_index_info.csv";
    const std::string indexFileFePath = "/data/local/tmp/smartperf/1/t_gpu_info.csv";
    const std::string gpuCounterfilePath = "/data/local/tmp/smartperfDevice";
    const std::string dubaiXpower = "/data/service/el2/100/xpower/dubai.db";
    const std::string dubaiFilePath = "/data/local/tmp/dubai/dubai.db";
    std::string tracefilePath = "";
    const std::string logFilePath = "/data/local/tmp/spdaemonlog/logfile.tar.gz";
    int sendFileSocket = -1;
    int sendFileSocketPort = -1;
    static const int fileSocketBufferSize = 8192;
    char fileSocketBuffer[fileSocketBufferSize] = {};
    bool isSetPid = false;
    SPTask &spTask = SPTask::GetInstance();
    std::thread udpStartCollect;

    ~SpThreadSocket()
    {
        if (udpStartCollect.joinable()) {
            udpStartCollect.join();
        }
    }
    std::shared_ptr<TaskManager> taskMgr_ {nullptr};
    ByTrace &bytrace = ByTrace::GetInstance();
    bool firstFlag = true;
    int maxTraceSize_ = 5;
    int collectTraceNum_ = 0;
};
}
}
#endif