
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
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <functional>
#include <vector>
#include <thread>
#include <future>
#include <map>
#include <mutex>
#include <climits>
#include "parameters.h"
#include "include/sp_csv_util.h"
#include "include/sdk_data_recv.h"
#include "include/GpuCounter.h"
#include "include/lock_frequency.h"
#include "include/sp_thread_socket.h"
#include "include/sp_profiler_factory.h"
#include "include/sp_log.h"
#include "include/sp_task.h"
#include "include/heartbeat.h"
#include "include/control_call_cmd.h"
#include "include/sp_profiler_factory.h"
#include "include/Network.h"
#include "include/startup_delay.h"
#include "include/Dubai.h"
#include "include/GameEvent.h"
#include "include/GetLog.h"
#include "include/RAM.h"
#include "include/FPS.h"
#include "include/hiperf.h"
#include "include/visual_effect_analysis.h"
#include "include/VisualEffectDisPatch.h"

#define SMARTPERF "smartperf"
namespace OHOS {
namespace SmartPerf {
std::string g_pkgName = "";
std::string g_pkgAndPid = "";
std::string SpThreadSocket::MapToString(std::map<std::string, std::string>& dataMap) const
{
    std::string result;
    int i = 0;
    std::string splitStr = "";
    for (auto iter = dataMap.cbegin(); iter != dataMap.cend(); ++iter) {
        printf("%s = %s\n", iter->first.c_str(), iter->second.c_str());
        if (i > 0) {
            splitStr = "$$";
        }
        result += splitStr + iter->first.c_str() + "||" + iter->second.c_str();
        i++;
    }
    return result;
}
std::string SpThreadSocket::SplitMsg(const std::string &recvBuf) const
{
    if (recvBuf.empty()) {
        LOGE("SplitMsg recvBuf is null");
        return recvBuf;
    }
    size_t pos = recvBuf.find("::");
    if (pos != std::string::npos) {
        std::vector<std::string> sps;
        SPUtils::StrSplit(recvBuf, "::", sps);
        if (sps.size() > 1) {
            return sps[1];
        } else {
            LOGE("SplitMsg sps size is zreo");
            return recvBuf;
        }
    } else {
        return recvBuf;
    }
}

void SpThreadSocket::Process(ProtoType type)
{
    std::cout << "Socket Process called!" << std::endl;
    SpServerSocket spSocket;
    spSocket.Init(type);
    if (type == ProtoType::TCP) {
        std::cout << "Socket TCP Init called!" << std::endl;
        WLOGI("Socket TCP Init called!");
        TypeTcp(spSocket);
    }
    if (type == ProtoType::UDP || type == ProtoType::UDPEX) {
        SocketHeartbeat();
        while (socketConnect == true) {
            spSocket.Recvfrom();
            HandleMsg(spSocket);
        }
    }
    std::cout << "Socket Process finished!" << std::endl;
    spSocket.Close();
}
SocketErrorType SpThreadSocket::CheckTcpToken(const std::string& recvStr,
    SpServerSocket &spSocket, const std::string& recvStrNoToken) const
{
    if (recvStr.find_last_of(":") == std::string::npos) {
        if (recvStr.find("SP_daemon -editor") != std::string::npos) {
            LOGI("Received string contains 'SP_daemon -editor', token check passed.");
            return SocketErrorType::OK;
        } else {
            LOGE("Token check failed: %s", recvStrNoToken.c_str());
            return SocketErrorType::TOKEN_CHECK_FAILED;
        }
    }
    std::string token = recvStr.substr(recvStr.find_last_of(":") + 1);
    token = token.substr(0, token.find(' '));
    std::string tcpSocketToken = SpThreadSocket::GetInstance().GetToken();
    LOGD("Comparing token with TCP token...");
    if (tcpSocketToken == "" && token == "-SESSIONID") {
        LOGI("Token is empty but received token is '-SESSIONID', token check passed.");
        return SocketErrorType::OK;
    }
    if (token != tcpSocketToken) {
        LOGE("Token mismatch.");
        return SocketErrorType::TOKEN_CHECK_FAILED;
    }
    LOGD("Token match");
    return SocketErrorType::OK;
}
void SpThreadSocket::TypeTcp(SpServerSocket &spSocket)
{
    SocketHeartbeat();
    WLOGI("Socket TCP Init Finished, Wait Client Socket Connect...");
    while (socketConnect == true) {
        int procFd = spSocket.Accept();
        std::cout << "Socket TCP procFd: " << procFd << std::endl;
        WLOGI("Accepted socket connection, procFd: %d", procFd);
        while (procFd > 0) {
            int reFd = spSocket.Recv();
            if (reFd < 0) {
                WLOGE("Error receiving data, reFd: %d", reFd);
                break;
            }
            std::string recvStr = spSocket.RecvBuf();
            std::string recvStrNoToken = recvStr.substr(0, recvStr.find("::"));
            LOGD("TCP recv data:%s", recvStr.c_str());
            WLOGD("Received data: %s", recvStrNoToken.c_str());
            // 解析消息 分发处理
            const SocketErrorType tokenStatus = CheckTcpToken(recvStr, spSocket, recvStrNoToken);
            WLOGI("Token check status: %d", tokenStatus);
            DealMsg(recvStr, spSocket, tokenStatus);
        }
    }
}
// TCP
void SpThreadSocket::InitRecv(const std::string& recvStr, SpServerSocket &spSocket, SocketConnectType type) const
{
    std::string errorInfo;
    std::string checkStr = recvStr.substr(std::string("init::").length());
    if (!SPTask::GetInstance().CheckTcpParam(checkStr, errorInfo) &&
        checkStr.find(SpThreadSocket::GetInstance().GetToken()) == std::string::npos) {
        WLOGE("Init error(%s)", errorInfo.c_str());
        if (type == SocketConnectType::CMD_SOCKET) {
            spSocket.Send("init::False,\"error\":" + errorInfo);
        } else {
            spSocket.Send(std::string("init::") + SocketErrorTypeToString(SocketErrorType::INIT_FAILED));
        }
        return;
    }
    if (recvStr.find("-lockfreq") != std::string::npos && SpThreadSocket::GetInstance().GetToken() == "") {
        WLOGE("'-lockfreq' must have a valid token.");
        return;
    }
    ErrCode code = SPTask::GetInstance().InitTask(SplitMsg(recvStr));
    if (type == SocketConnectType::CMD_SOCKET) {
        spSocket.Send(std::string("init::") + ((code == ErrCode::OK) ? "True" : "False"));
        WLOGI("Sent init::"  + ((code == ErrCode::OK) ? "True" : "False"));
        return;
    }
    if (code == ErrCode::OK) {
        spSocket.Send("init::True");
        WLOGI("Sent init::True response");
    } else {
        spSocket.Send(std::string("init::") + SocketErrorTypeToString(SocketErrorType::INIT_FAILED));
        WLOGE("Sent init::%d for failure", SocketErrorType::INIT_FAILED);
    }
}
void SpThreadSocket::StartRecv(SpServerSocket &spSocket)
{
    if (flagRunning) {
        spSocket.Send("SP_daemon is running");
        return;
    }
    auto lambdaTask = [](const std::string &data) {
        std::cout << data << std::endl;
    };
    ErrCode code = SPTask::GetInstance().StartTask(lambdaTask);
    if (code == ErrCode::OK) {
        spSocket.Send("start::True");
        flagRunning = true;
        WLOGI("Sent start::True message to socket.");
    } else if (code == ErrCode::FAILED) {
        spSocket.Send("start::False");
        WLOGE("Sent start::False message to socket.");
        return;
    }
    SPTask::GetInstance().StartRecord();
}
void SpThreadSocket::StartRecvRealtime(SpServerSocket &spSocket) const
{
    auto lambdaTask = [&spSocket](const std::string &data) { spSocket.Send(data); };
    ErrCode code = SPTask::GetInstance().StartTask(lambdaTask);
    if (code == ErrCode::OK) {
        spSocket.Send("start::True");
        WLOGI("Sent start::True message to socket.");
    } else if (code == ErrCode::FAILED) {
        spSocket.Send(std::string("start::") + SocketErrorTypeToString(SocketErrorType::START_FAILED));
        WLOGE("Sent start::" + SocketErrorTypeToString(SocketErrorType::START_FAILED) + " message to socket.");
    }
}
void SpThreadSocket::StopRecvRealtime(SpServerSocket &spSocket)
{
    ErrCode code = SPTask::GetInstance().StopTask();
    if (code == ErrCode::OK) {
        spSocket.Send("stop::True");
        WLOGI("Sent stop::True message to socket.");
        flagRunning = false;
        spSocket.Close();
    } else if (code == ErrCode::FAILED) {
        spSocket.Send(std::string("stop::") + SocketErrorTypeToString(SocketErrorType::STOP_FAILED));
        WLOGE("Sent stop::" + SocketErrorTypeToString(SocketErrorType::STOP_FAILED) + " message to socket.");
    }
}
void SpThreadSocket::StartRecvRecord(SpServerSocket &spSocket) const
{
    ErrCode code = SPTask::GetInstance().StartRecord();
    if (code == ErrCode::OK) {
        spSocket.Send("startRecord::True");
        WLOGI("Sent startRecord::True message to socket.");
    } else {
        spSocket.Send(std::string("startRecord::") + SocketErrorTypeToString(SocketErrorType::START_RECORD_FAILED));
        WLOGE("Sent startRecord::" + SocketErrorTypeToString(SocketErrorType::START_RECORD_FAILED) +
        " message to socket.");
    }
}
void SpThreadSocket::StopRecvRecord(SpServerSocket &spSocket) const
{
    ErrCode code = SPTask::GetInstance().StopRecord();
    if (code == ErrCode::OK) {
        spSocket.Send("stopRecord::True");
        WLOGI("Sent stopRecord::True message to socket.");
    } else {
        spSocket.Send(std::string("stopRecord::") + SocketErrorTypeToString(SocketErrorType::STOP_RECORD_FAILED));
        WLOGE("Sent stopRecord::" + SocketErrorTypeToString(SocketErrorType::STOP_RECORD_FAILED) +
        " message to socket.");
    }
}
void SpThreadSocket::SendTokenFailedMessage(SpServerSocket &socket, const std::string &message) const
{
    if (message.find("init:::") != std::string::npos ||
        message.find("start:::") != std::string::npos) {
        WLOGI("Skipping token check failure for init::: or start::: command.");
        return;
    }
    const std::vector<std::string> messageType = {
        "init::",
        "start::",
        "stop::",
        "startRecord::",
        "stopRecord::",
    };
    for (auto& it : messageType) {
        if (message.find(it) != std::string::npos) {
            WLOGE("Sending token check failed message for command: %s", it.c_str());
            socket.Send(it + SocketErrorTypeToString(SocketErrorType::TOKEN_CHECK_FAILED));
            return;
        }
    }
    WLOGW("No matching command found for token check failure in message: %s", message.c_str());
}
SocketErrorType SpThreadSocket::CheckUdpToken(const std::string& recvStr) const
{
    // 不需要校验 token
    if (isNeedUdpToken == false) {
        return SocketErrorType::OK;
    }
    // device 启动时发送，不做校验
    if (recvStr == "get_daemon_version" || recvStr.find("set_pkgName::") != std::string::npos) {
        return SocketErrorType::OK;
    }
    // command:::token
    if (recvStr.find_last_of(":::") == std::string::npos) {
        WLOGE("Token check failed: %s", recvStr.c_str());
        return SocketErrorType::TOKEN_CHECK_FAILED;
    }
    // 提取 token
    std::string token = recvStr.substr(recvStr.find_last_of(":::") + 1);
    token = token.substr(0, token.find(' '));

    std::string udpSocketToken = SpThreadSocket::GetInstance().GetToken();
    LOGD("Comparing token with Udp token...");
    // token 校验
    if (token != udpSocketToken) {
        WLOGE("Token mismatch.");
        return SocketErrorType::TOKEN_CHECK_FAILED;
    }
    LOGD("UDP token check passed");
    return SocketErrorType::OK;
}
void SpThreadSocket::DealMsg(const std::string& recvStr, SpServerSocket &spSocket, SocketErrorType tokenStatus)
{
    SocketHeartbeat();
    if (tokenStatus == SocketErrorType::TOKEN_CHECK_FAILED) {
        SendTokenFailedMessage(spSocket, recvStr);
        return;
    }
    if (recvStr.find("init:::") != std::string::npos) {
        WLOGI("Processing 'init:::' command.");
        if (recvStr.find("-f") != std::string::npos) {
            InitRecv(recvStr + " -j", spSocket, SocketConnectType::CMD_SOCKET);
        } else {
            InitRecv(recvStr, spSocket, SocketConnectType::CMD_SOCKET);
        }
        FPS::GetInstance().isNeedDump = true;
        FPS::GetInstance().isStartStop = true;
    } else if (recvStr.find("start:::") != std::string::npos) {
        WLOGI("Processing 'start:::' command.");
        StartRecv(spSocket);
    } else if (recvStr.find("init::") != std::string::npos) {
        WLOGI("Processing 'init::' command.");
        InitRecv(recvStr, spSocket, SocketConnectType::EDITOR_SOCKET);
    } else if (recvStr.find("start::") != std::string::npos) {
        WLOGI("Processing 'start::' command.");
        StartRecvRealtime(spSocket);
    } else if (recvStr.find("stop::") != std::string::npos) {
        WLOGI("Processing 'stop::' command.");
        SpProfilerFactory::editorFlag = false;
        StopRecvRealtime(spSocket);
    } else if (recvStr.find("startRecord::") != std::string::npos) {
        WLOGI("Processing 'startRecord::' command.");
        StartRecvRecord(spSocket);
    } else if (recvStr.find("stopRecord::") != std::string::npos) {
        WLOGI("Processing 'stopRecord::' command.");
        SpProfilerFactory::editorFlag = false;
        StopRecvRecord(spSocket);
    } else if (recvStr.find("SP_daemon -editor") != std::string::npos) {
        EditorRecv(recvStr, spSocket);
    } else {
        WLOGW("Received unknown command: %s", recvStr.c_str());
    }
}
void SpThreadSocket::EditorRecv(const std::string& recvStr, const SpServerSocket &spSocket) const
{
    std::vector<std::string> vec;
    size_t size = recvStr.size();
    size_t j = 0;
    for (size_t i = 0; i < size; i++) {
        if (recvStr[i] == ' ') {
            vec.push_back(recvStr.substr(j, i - j));
            j = i + 1;
        }
    }
    vec.push_back(recvStr.substr(j, size - j));
    const int type = 2;
    if (vec[type] == "findAppPage") {
        BackDesktop();
    }
    OHOS::SmartPerf::ControlCallCmd controlCallCmd;
    std::string result = controlCallCmd.GetResult(vec);
    spSocket.Send(result);
}
void SpThreadSocket::BackDesktop() const
{
    std::string cmdResult;
    std::string uinput = CMD_COMMAND_MAP.at(CmdCommand::UINPUT_BACK);
    SPUtils::LoadCmd(uinput, cmdResult);
}
// UDP
void SpThreadSocket::RemoveToken(std::string &recvMessage)
{
    if (recvMessage.find(":::") != std::string::npos) {
        recvMessage = recvMessage.substr(0, recvMessage.find(":::"));
    }
}

void SpThreadSocket::HandleMsg(SpServerSocket &spSocket)
{
    std::string retCode = "";
    auto iterator = MESSAGE_MAP.begin();
    while (iterator != MESSAGE_MAP.end()) {
        std::string recvBuf = spSocket.RecvBuf();
        HeartbeatDetection(recvBuf);
        const SocketErrorType tokenStatus = CheckUdpToken(recvBuf);
        if (tokenStatus == SocketErrorType::TOKEN_CHECK_FAILED) {
            spSocket.Sendto(std::string("token failed"));
            spSocket.Close();
            return;
        }
        RemoveToken(recvBuf);
        recvBuf = GetTime(recvBuf);
        if (recvBuf.find("init::") != std::string::npos && firstFlag) {
            FPS::GetInstance().SetHapFlag();
            HandleMsgTrace(recvBuf);
            UdpStartInitFunc(recvBuf, spSocket);
            firstFlag = false;
            break;
        }
        if (!SPUtils::IsSubString(recvBuf, iterator->second)) {
            ++iterator;
            continue;
        }
        SpProfiler *profiler = SpProfilerFactory::GetProfilerItem(iterator->first);
        if (profiler == nullptr) {
            HandleNullMsg(spSocket, profiler, retCode, recvBuf, iterator);
        } else {
            std::map<std::string, std::string> data;
            if (iterator->first == MessageType::CATCH_NETWORK_TRAFFIC) {
                Network::GetInstance().IsFindHap();
                profiler->ItemData(); // record the collection point for the first time,no need to return
                data["network_traffic"] = "true";
            } else if (iterator->first == MessageType::GET_NETWORK_TRAFFIC) {
                Network::GetInstance().IsStopFindHap();
                data = profiler->ItemData();
                data["network_traffic"] = "true";
            } else if (iterator->first == MessageType::GET_LOG) {
                GetSocketPort(recvBuf);
                data = profiler->ItemData();
            } else {
                GetProcessIdByPkgName(iterator);
                data = profiler->ItemData();
            }
            HandleUDPMsg(spSocket, data, retCode, iterator);
        }
        break;
    }
}

void SpThreadSocket::HandleMsgTrace(std::string& recvMessage)
{
    const std::string traceWord = "-TRACE::";
    const size_t startPos = recvMessage.find(traceWord);
    const size_t tarceLength = traceWord.length();
    const size_t colonLength = 2;
    if (startPos != std::string::npos) {
        size_t tracePos = startPos + tarceLength;
        size_t endPos = recvMessage.find(" ", startPos);
        bytrace.jittersAndLowFps = recvMessage.substr(tracePos, endPos - tracePos);
        recvMessage.erase(tracePos - colonLength, colonLength + bytrace.jittersAndLowFps.length());
    }
}

void SpThreadSocket::HeartbeatDetection(const std::string& recvBuf)
{
    if (recvBuf.size() != 0) {
        Heartbeat &heartbeat = Heartbeat::GetInstance();
        heartbeat.UpdatestartTime();
    }
}

void SpThreadSocket::UdpStartInitFunc(const std::string& recvBuf, SpServerSocket &spSocket)
{
    if (taskMgr_ != nullptr) {
        taskMgr_->Stop();
        taskMgr_->WriteToCSV();
    }
    taskMgr_ = std::make_shared<TaskManager>(true);
    auto lambdaTask = [&spSocket](const std::string &data) { spSocket.Sendto(data); };
    taskMgr_->SetIPCCallback(lambdaTask);
    taskMgr_->AddTask(recvBuf);
    spTask.SetAppCmd(recvBuf);
    spTask.SetAppInitFlag();

    std::string fileDir = "/data/local/tmp/smartperf/" + spTask.GetCurTaskInfo().sessionId;
    spTask.CreatPath(fileDir);
    taskMgr_->SetFilePath(fileDir + "/t_index_info.csv");
}

int SpThreadSocket::FileSocketConnect()
{
    sendFileSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (sendFileSocket < 0) {
        WLOGE("Create log file socket failed, errno: %d", errno);
        return -1;
    }
    struct sockaddr_in socketAddr = {0};
    socketAddr.sin_family = AF_INET;
    socketAddr.sin_port = htons(sendFileSocketPort);
    socketAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (connect(sendFileSocket, reinterpret_cast<struct sockaddr *>(&socketAddr), sizeof(socketAddr)) < 0) {
        WLOGE("Connect log file socket failed, errno: %d", errno);
        return -1;
    }
    WLOGI("Connect log file socket success, socket: %d", sendFileSocket);
    return sendFileSocket;
}

int SpThreadSocket::SendFile(const std::string& filePath)
{
    char filePathChar[PATH_MAX] = {0x00};
    if ((realpath(filePath.c_str(), filePathChar) == nullptr)) {
        WLOGE("%s is not exist.", filePath.c_str());
        return -1;
    }
    std::ifstream logFile(filePathChar, std::ios::binary);
    if (!logFile.is_open()) {
        WLOGE("Open log file failed");
        close(sendFileSocket);
        sendFileSocket = -1;
        return -1;
    }
    WLOGI("logfile exists, sending...");
    logFile.seekg(0, std::ios::end);
    std::streamsize fileSize = logFile.tellg();
    logFile.seekg(0, std::ios::beg);
    std::streamsize totalSent = 0;
    while (!logFile.eof()) {
        logFile.read(fileSocketBuffer, sizeof(fileSocketBuffer));
        std::streamsize bytesRead = logFile.gcount();
        ssize_t bytesSent = send(sendFileSocket, fileSocketBuffer, bytesRead, 0);
        if (bytesSent < 0) {
            WLOGE("Send log file failed");
            logFile.close();
            close(sendFileSocket);
            sendFileSocket = -1;
            return -1;
        }
        totalSent += bytesSent;
        if (bytesSent != bytesRead) {
            WLOGE("Incomplete send: sent %zd bytes out of %zd", bytesSent, bytesRead);
            logFile.close();
            close(sendFileSocket);
            sendFileSocket = -1;
            return -1;
        }
    }
    if (totalSent != fileSize) {
        WLOGE("File size mismatch: sent %zd bytes, file size %zd", totalSent, fileSize);
        return -1;
    }
    logFile.close();
    close(sendFileSocket);
    sendFileSocket = -1;
    WLOGI("Send log file success, bytes: %zd", totalSent);
    return 0;
}

void SpThreadSocket::ConnectAndSendFile(SpServerSocket &spSocket, const std::string filePath)
{
    if (filePath.empty()) {
        WLOGE("Connect filePath does not exist.");
        return;
    }
    if (sendFileSocketPort == -1) {
        return;
    }
    std::thread sendSizeThread([&spSocket, filePath]() {
        size_t fileSize = SPUtils::GetFileSize(filePath);
        if (fileSize == 0) {
            LOGE("UDP ConnectAndSendFile recv GetFileSize fileSize: (%d)", fileSize);
            return;
        }
        std::string sendFileSizeMsg = "SendFileSize:::" + std::to_string(fileSize);
        LOGI("UDP START sendFileSizeMsg = %s", sendFileSizeMsg.c_str());
        spSocket.Sendto(sendFileSizeMsg);
        LOGI("UDP Sendto sendFileSizeMsg = %s", sendFileSizeMsg.c_str());
    });

    std::thread sendFileThread([this, filePath]() {
        int fileSocket = -1;
        int connectCount = 0;
        const int maxTryCount = 2;

        while (fileSocket < 0) {
            WLOGI("Connect file log socket, try times: %d", connectCount + 1);
            if (connectCount > maxTryCount) {
                WLOGE("Connect file log socket failed");
                return;
            }
            connectCount++;
            fileSocket = FileSocketConnect();
        }

        int ret = SendFile(filePath);
        if (ret < 0) {
            WLOGE("Failed to send file");
            return;
        }
    });

    sendSizeThread.join();
    sendFileThread.join();
}

void SpThreadSocket::HandleUDPMsg(SpServerSocket &spSocket, std::map<std::string, std::string>& data,
    std::string& retCode, std::unordered_map<MessageType, std::string>::const_iterator iterator)
{
    std::cout << "iterator->first: " << static_cast<int>(iterator->first) << std::endl;
    if (iterator->first == MessageType::GET_CUR_FPS) {
        FPS::GetInstance().isLowCurFps = true;
        std::string resultfps = "vfps||";
        for (auto iter = data.cbegin(); iter != data.cend(); ++iter) {
            if (iter->first != "fpsJitters") {
                std::string temp = iter->second + "@@";
                resultfps += std::string(temp.c_str());
            }
        }
        spSocket.Sendto(resultfps);
        LOGD("UDP send Cur_resultfps = %s", resultfps.c_str());
    } else if (iterator->first == MessageType::GET_CPU_FREQ_LOAD) {
        FetchCpuStats(spSocket, data);
    } else if (iterator->first == MessageType::GET_LOG) {
        ConnectAndSendFile(spSocket, logFilePath);
        GetLog::GetInstance().RemoveLogFile();
    } else {
        retCode = MapToString(data);
        spSocket.Sendto(retCode);
        LOGD("UDP send retCode = %s", retCode.c_str());
    }
}
void SpThreadSocket::SocketHeartbeat() const
{
    Heartbeat &heartbeat = Heartbeat::GetInstance();
    heartbeat.UpdatestartTime();
}
void SpThreadSocket::FetchCpuStats(SpServerSocket &spSocket, std::map<std::string, std::string>& data) const
{
    std::string resultCpuFrequency = "";
    std::string resultCpuUsage = "";
    std::string resultCpu = "";
    int cpuFrequencyNum = 0;
    int cpuUsageNum = 0;
    int cpuFlag = 1;
    while (cpuFlag) {
        resultCpuFrequency = "cpu" + std::to_string(cpuFrequencyNum) + "Frequency";
        resultCpuUsage = "cpu" + std::to_string(cpuUsageNum) + "Usage";
        auto iterCpuFrequency = data.find(resultCpuFrequency);
        auto iterCpuUsage = data.find(resultCpuUsage);
        if (iterCpuFrequency != data.end()) {
            resultCpuFrequency += "||" + iterCpuFrequency->second;
            resultCpu += "$$" + resultCpuFrequency;
            cpuFrequencyNum++;
        } else {
            cpuFlag = 0;
        }
        if (iterCpuUsage != data.end()) {
            resultCpuUsage += "||" + iterCpuUsage->second;
            resultCpu += "$$" + resultCpuUsage;
            cpuUsageNum++;
        } else {
            cpuFlag = 0;
        }
    }
    spSocket.Sendto(resultCpu);
    LOGD("UDP send resultCpu = %s", resultCpu.c_str());
}
void SpThreadSocket::HandleNullMsg(SpServerSocket &spSocket, SpProfiler *profiler, std::string& retCode,
    const std::string& recvBuf, std::unordered_map<MessageType, std::string>::const_iterator iterator)
{
    if (iterator->first == MessageType::SET_PKG_NAME) {
        isSetPid = false;
        retCode = SplitMsg(recvBuf);
        if (recvBuf.find(SMARTPERF) != std::string::npos && retCode.find(SMARTPERF) != std::string::npos) {
            Dubai::dubaiPkgName = retCode;
            LOGD("UDP send smartperf: (%s)", Dubai::dubaiPkgName.c_str());
        } else {
            if (retCode.find("$") != std::string::npos) {
                g_pkgAndPid = retCode;
                g_pkgName = SpGetPkg(g_pkgAndPid);
            } else {
                g_pkgName = retCode;
            }
            std::thread([this]() { this->ResetValue(g_pkgName); }).detach();
            LOGD("HandleNullMsg pkgName: (%s)", g_pkgName.c_str());
        }
        spSocket.Sendto(retCode);
        LOGD("UDP send PkgName = %s", retCode.c_str());
    } else if (profiler == nullptr && (iterator->first == MessageType::GET_APP_TYPE)) {
        retCode = SplitMsg(recvBuf);
        std::thread([this, retCode]() { this->ResetValue(retCode); }).detach();
    } else if (profiler == nullptr && (iterator->first == MessageType::GET_DAEMON_VERSION)) {
        retCode = "Version: " + SPUtils::GetVersion();
        spSocket.Sendto(retCode);
    } else if (iterator->first == MessageType::CATCH_ONE_TRACE) {
        bytrace.hiviewTrace = SplitMsg(recvBuf);
        bytrace.CpTraceFile();
    } else if (iterator->first == MessageType::CATCH_TRACE_FINISH) {
        tracefilePath = "";
        GetSocketPort(recvBuf);
        ConnectAndSendFile(spSocket, tracefilePath);
    } else if (iterator->first == MessageType::GET_CPU_NUM) {
        retCode = SPUtils::GetCpuNum();
        spSocket.Sendto(retCode);
        LOGD("UDP send cpuNum = %s", retCode.c_str());
    } else if (iterator->first == MessageType::BACK_TO_DESKTOP) {
        BackDesktop();
    } else if (iterator->first == MessageType::GET_CYCLE) {
        VisualEffectAnalysis::GetInstance().CapturingTraces();
    } else {
        HandleNullAddMsg(spSocket, profiler, retCode, recvBuf, iterator);
    }
}

void SpThreadSocket::GetProcessIdByPkgName(std::unordered_map<MessageType, std::string>::const_iterator iterator)
{
    if (iterator->first == MessageType::GET_FPS_AND_JITTERS || iterator->first == MessageType::GET_CUR_FPS ||
        iterator->first == MessageType::GET_RAM_INFO) {
        if (!SpProfilerFactory::editorFlag && isSetPid == false) {
            FPS::GetInstance().isHistoryHap = true;
            std::string pkgName = g_pkgName;
            std::string pkgAndPid = g_pkgAndPid;
            LOGD("SpProfilerFactory::g_pkgName(%s)", g_pkgName.c_str());
            std::string processId = "";
            std::string processIds = "";
            FPS::GetInstance().isPreset = IsPreset(pkgAndPid);
            if (FPS::GetInstance().isPreset) {
                processId = SpGetPid(pkgAndPid);
            } else {
                OHOS::SmartPerf::StartUpDelay sp;
                processId = sp.GetPidByPkg(pkgName, &processIds);
            }
            SpProfilerFactory::SetProfilerPidByPkg(processId, processIds);
            SpProfilerFactory::SetProfilerPkg(pkgName);
            isSetPid = true;
        }
    }
}

void SpThreadSocket::ResetValue(std::string retCode) const
{
    FPS::GetInstance().isGameApp = SPUtils::GetIsGameApp(retCode);
    RAM::GetInstance().SetHapFirstFlag();
}
void SpThreadSocket::HandleNullAddMsg(SpServerSocket &spSocket, SpProfiler *profiler, std::string& retCode,
    const std::string& recvBuf, std::unordered_map<MessageType, std::string>::const_iterator iterator)
{
    Dubai &db = Dubai::GetInstance();
    if (iterator->first == MessageType::START_DUBAI_DB) {
        std::thread dStart([&db]() { db.CallBeginAndFinish(); });
        dStart.detach();
    } else if (iterator->first == MessageType::SET_DUBAI_DB) {
        GetSocketPort(recvBuf);
        db.CallBeginAndFinish();
        FPS::GetInstance().isLowCurFps = false;
        db.MoveDubaiDb(dubaiXpower);
        ConnectAndSendFile(spSocket, dubaiFilePath);
        retCode = "get_dubai_db";
        LOGD("UDP send GetDubaiDb Message: (%s)", retCode.c_str());
        spSocket.Sendto(retCode);
        LOGD("UDP send DuBai get finish");
    } else if (iterator->first == MessageType::CHECK_UDP_STATUS) {
        retCode = "UDP status is normal";
        spSocket.Sendto(retCode);
        LOGD("UDP status is normal");
    } else if (iterator->first == MessageType::SAVE_GPU_COUNTER) {
        GetSocketPort(recvBuf);
        std::unique_lock<std::mutex> lock(GpuCounter::GetInstance().GetGpuCounterLock());
        ConnectAndSendFile(spSocket, gpuCounterfilePath + "/gpu_counter.csv");
    } else if (iterator->first == MessageType::APP_STOP_COLLECT) {
        if (taskMgr_ != nullptr) {
            // UDP (device) 停止时，设置GPU_COUNTER保存路径
            firstFlag = true;
            SPUtils::CreateDir(gpuCounterfilePath);
            GpuCounter::GetInstance().SetSavePathDirectory(gpuCounterfilePath);
            taskMgr_->ClearShaderFile();
            taskMgr_->SetHapFlag(false);
            taskMgr_->Stop();
            SPUtils::OverDumpFun();
            retCode = Hiperf::GetInstance().ReturnHiperfData();
            spSocket.Sendto(retCode);
            taskMgr_->WriteToCSV();
        }
        spTask.ClearStopFlag();
    } else {
        UdpStartMessProcess(spSocket, profiler, retCode, recvBuf, iterator);
    }
}

void SpThreadSocket::UdpStartMessProcess(SpServerSocket &spSocket, SpProfiler *profiler, std::string& retCode,
    const std::string& recvBuf, std::unordered_map<MessageType, std::string>::const_iterator iterator)
{
    if (iterator->first == MessageType::APP_START_COLLECT) {
        if (taskMgr_ != nullptr) {
            taskMgr_->AddTask(&SdkDataRecv::GetInstance(), false);
        }
        bytrace.ClearTraceFiles();
        StartHapCollecting(spSocket);
    } else if (iterator->first == MessageType::APP_RECEIVE_DATA_ON && !firstFlag) {
        if (taskMgr_ != nullptr) {
            LOGD("Start to display data in real time");
            taskMgr_->SetHapFlag(true);
            taskMgr_->EnableIPCCallback();
        }
    } else if (iterator->first == MessageType::APP_RECEIVE_DATA_OFF && !firstFlag) {
        if (taskMgr_ != nullptr) {
            LOGD("Real time data display ends");
            taskMgr_->DisableIPCCallback();
        }
    } else if (iterator->first == MessageType::APP_PAUSE_COLLECT && !firstFlag) {
        if (taskMgr_ != nullptr) {
            LOGD("Pause Collection");
            SPUtils::CreateDir(gpuCounterfilePath);
            GpuCounter::GetInstance().SetSavePathDirectory(gpuCounterfilePath);
            GpuCounter::GetInstance().SetIsPause(true);
            taskMgr_->Pause();
        }
    } else if (iterator->first == MessageType::APP_RESUME_COLLECT && !firstFlag) {
        LOGD("Resuming Collection");
        taskMgr_->Resume();
        GpuCounter::GetInstance().SetIsPause(false);
    } else if (iterator->first == MessageType::GET_INDEX_INFO) {
        GetSocketPort(recvBuf);
        ConnectAndSendFile(spSocket, indexFilePath);
    } else if (iterator->first == MessageType::GET_GPU_INFO) {
        GetSocketPort(recvBuf);
        ConnectAndSendFile(spSocket, indexFileFePath);
    } else {
        GetCatchTraceResult(retCode, spSocket,  iterator, recvBuf);
    }
}

void SpThreadSocket::GetCatchTraceResult(std::string& retCode, SpServerSocket &spSocket,
    std::unordered_map<MessageType, std::string>::const_iterator iterator, const std::string& recvBuf)
{
    if (iterator->first == MessageType::CATCH_TRACE_SUCCESS) {
        if (!std::filesystem::exists(traceDir)) {
            SPUtils::CreateDir(traceDir);
        }
        SendTraceFile(recvBuf, spSocket);
    } else if (iterator->first == MessageType::CAPTURE_FAILED) {
        VisualEffectDisPatch::GetInstance().SetCatchTraceFlag();
    } else if (iterator->first == MessageType::OVER_SPECIFICATION) {
        VisualEffectDisPatch::GetInstance().SetSpeciFlag();
    } else {
        retCode = iterator->second;
        spSocket.Sendto(retCode);
        LOGD("UDP send Data:(%s)", retCode.c_str());
    }
}

void SpThreadSocket::SendTraceFile(const std::string& recvBuf, SpServerSocket &spSocket)
{
    if (collectTraceNum_ < maxTraceSize_) {
        std::string traceFileName = SplitMsg(recvBuf);
        size_t pos = traceFileName.find("trace_");
        if (pos != std::string::npos) {
            uint64_t traceTime = 3;
            std::string errMassage = "";
            std::string traceFile = traceFileName.substr(pos);
            const std::string sysTraceFilePath = traceOriginPath + traceFile;
            const std::string sendTraceFileName = traceDir + "profilerTrace" +
                std::to_string(collectTraceNum_) + ".ftrace";
            SPUtils::ConvertTraceByTime(sysTraceFilePath, sendTraceFileName, traceTime, errMassage);
            GetSocketPort(recvBuf);
            ConnectAndSendFile(spSocket, sendTraceFileName);
            collectTraceNum_++;
        } else {
            spSocket.Sendto(std::string("Over_specification::Times"));
            VisualEffectDisPatch::GetInstance().SetSpeciFlag();
        }
    }
}
std::string SpThreadSocket::SocketErrorTypeToString(SocketErrorType errorType) const
{
    switch (errorType) {
        case SocketErrorType::OK:
            return "OK";
        case SocketErrorType::TOKEN_CHECK_FAILED:
            return "TOKEN_CHECK_FAILED";
        case SocketErrorType::INIT_FAILED:
            return "INIT_FAILED";
        case SocketErrorType::START_FAILED:
            return "START_FAILED";
        case SocketErrorType::STOP_FAILED:
            return "STOP_FAILED";
        case SocketErrorType::START_RECORD_FAILED:
            return "START_RECORD_FAILED";
        case SocketErrorType::STOP_RECORD_FAILED:
            return "STOP_RECORD_FAILED";
        default:
            return "UNKNOWN";
    }
}
void SpThreadSocket::GetSocketPort(const std::string& buffer)
{
    if (buffer.find("::") != std::string::npos) {
        std::string portStr = buffer.substr(buffer.find("::") + 2);
        std::string fileName = "";
        if (portStr.find(":::") != std::string::npos) {
            portStr = portStr.substr(0, portStr.find(":::"));
        }

        if (portStr.find("$") != std::string::npos) {
            fileName = portStr.substr(portStr.find("$") + 1);
            portStr = portStr.substr(0, portStr.find("$"));
            tracefilePath = traceOriginPath + fileName;
        }
        
        int port = SPUtilesTye::StringToSometype<int>(portStr);
        if (port <= 0) {
            WLOGE("Invalid port number: %d", port);
            sendFileSocketPort = -1;
        } else {
            WLOGI("Get File log UDP message received, port is %d", port);
            sendFileSocket = -1;
            sendFileSocketPort = port;
        }
    } else {
        WLOGE("Get File log UDP message received, but port is not found");
        sendFileSocketPort = -1;
    }
}
std::string SpThreadSocket::SpGetPkg(const std::string &spMsg) const
{
    if (spMsg.empty()) {
        return spMsg;
    }
    size_t pos = spMsg.find("$");
    if (pos != std::string::npos) {
        std::vector<std::string> sps;
        SPUtils::StrSplit(spMsg, "$", sps);
        if (sps.size() > 1) {
            return sps[0];
        } else {
            return spMsg;
        }
    } else {
        return spMsg;
    }
}

std::string SpThreadSocket::SpGetPid(const std::string &spMsg) const
{
    if (spMsg.empty()) {
        LOGE("spMsg is null");
        return spMsg;
    }
    size_t pos = spMsg.find("$");
    if (pos != std::string::npos) {
        std::vector<std::string> sps;
        SPUtils::StrSplit(spMsg, "$", sps);
        if (sps.size() > 1) {
            return sps[1];
        } else {
            LOGE("SpGetPid sps size is zreo");
            return "";
        }
    } else {
        return "";
    }
}

bool SpThreadSocket::IsPreset(const std::string &spMsg) const
{
    return spMsg.find("$") != std::string::npos;
}

void SpThreadSocket::SetToken(const std::string& token)
{
    checkToken = token;
}

std::string SpThreadSocket::GetToken() const
{
    return checkToken;
}

void SpThreadSocket::SetNeedUdpToken(bool isNeed)
{
    isNeedUdpToken = isNeed;
}

void SpThreadSocket::StartHapCollecting(SpServerSocket &spSocket)
{
    LOGD("UDP START Task starting...");
    RAM &ram = RAM::GetInstance();
    ram.SetFirstFlag();
    if (udpStartCollect.joinable()) {
        udpStartCollect.join();
    }
    udpStartCollect = std::thread([this]() {
        if (taskMgr_ == nullptr) {
            return;
        }
        taskMgr_->Start();
        taskMgr_->SetRecordState(true);
        taskMgr_->Wait();
        LOGD("Data collecting thread exiting.");
    });
    return;
}

std::vector<std::string> SpThreadSocket::split(const std::string &str, const std::string &delimiter)
{
    std::vector<std::string> tokens;
    size_t start = 0;
    size_t end = str.find(delimiter);
    while (end != std::string::npos) {
        tokens.push_back(str.substr(start, end - start));
        start = end + delimiter.length();
        end = str.find(delimiter, start);
    }
    //添加最后一个片段
    tokens.push_back(str.substr(start));
    return tokens;
}

std::string SpThreadSocket::GetTime(std::string &recvBuf)
{
    if (recvBuf.find("***") != std::string::npos && recvBuf.find("&&&") == std::string::npos) {
        size_t lastStarPos = recvBuf.rfind('*');
        if (lastStarPos != std::string::npos) {
            std::string result = recvBuf.substr(lastStarPos + 1);
            int time = SPUtilesTye::StringToSometype<int>(result);
            VisualEffectAnalysis::GetInstance().SetTraceTime(time);
        }
        size_t pos = recvBuf.find('*');
        if (pos != std::string::npos) {
            recvBuf = recvBuf.substr(0, pos);
        }
    } else {
        GetTraceStartPoint(recvBuf);
    }
    return recvBuf;
}

void SpThreadSocket::GetTraceStartPoint(std::string &recvBuf)
{
    if (recvBuf.find("&&&") == std::string::npos) {
        return;
    }

    std::vector<std::string> parts = split(recvBuf, "&&&");
    for (size_t i = 0; i < parts.size(); ++i) {
        if (parts[i].find("***") != std::string::npos) {
            size_t lastStarPos = parts[i].rfind('*');
            if (lastStarPos != std::string::npos) {
                std::string result = parts[i].substr(lastStarPos + 1);
                int time = SPUtilesTye::StringToSometype<int>(result);
                VisualEffectAnalysis::GetInstance().SetTraceTime(time);
            }

            size_t pos = parts[i].find('*');
            if (pos != std::string::npos) {
                recvBuf = parts[i].substr(0, pos);
            }
        }

        if (parts[i].find("begin$$$$$$") != std::string::npos) {
            std::string result = parts[i].substr(11);
            VisualEffectAnalysis::GetInstance().SetTraceBegin(result);
        }

        if (parts[i].find("over$$$$$$") != std::string::npos) {
            std::string result = parts[i].substr(10);
            VisualEffectAnalysis::GetInstance().SetTraceEnd(result);
        }
    }
}
}
}