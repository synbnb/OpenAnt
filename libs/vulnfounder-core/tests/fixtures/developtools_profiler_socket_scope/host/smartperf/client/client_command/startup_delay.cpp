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
#include <thread>
#include <cstdio>
#include <ios>
#include <vector>
#include <iostream>
#include <sstream>
#include <regex>
#include <fstream>
#include <algorithm>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "include/startup_delay.h"
#include "include/sp_utils.h"
#include "include/sp_log.h"
#include "include/common.h"

namespace OHOS {
namespace SmartPerf {
const int MAX_CHAR_SIZE = 1024;
std::vector<std::string> g_pidParams;
StartUpDelay::StartUpDelay() {}
StartUpDelay::~StartUpDelay() {}
void StartUpDelay::GetTrace(const std::string &traceName) const
{
    std::string result;
    std::string cmdString;
    if (SPUtils::IsHmKernel()) {
        cmdString = CMD_COMMAND_MAP.at(CmdCommand::HITRACE_1024);
    } else {
        cmdString = CMD_COMMAND_MAP.at(CmdCommand::HITRACE_2048);
    }
    SPUtils::LoadCmd(cmdString + traceName, result);
    LOGD("GetTrace : %s", (cmdString + traceName).c_str());
    if (result.find("OpenRecording failed") != std::string::npos) {
        std::string str;
        std::string traceFinishStr = "hitrace --trace_finish";
        SPUtils::LoadCmd(traceFinishStr, str);
        SPUtils::LoadCmd(cmdString + traceName, result);
    }
}

void StartUpDelay::GetHisysId() const
{
    int time = 10;
    sleep(time);
    std::string str = "";
    std::string cmd = HISYSEVENT_CMD_MAP.at(HisyseventCmd::HISYSEVENT);
    SPUtils::LoadCmd(cmd, str);
    std::stringstream ss(str);
    std::string line = "";
    getline(ss, line);
    std::stringstream ssLine(line);
    std::string word = "";
    std::string secondStr;
    int count = 0;
    int num = 2;
    while (ssLine >> word) {
        count++;
        if (count == num) {
            secondStr = word;
            break;
        }
    }
    std::string killCmd = CMD_COMMAND_MAP.at(CmdCommand::KILL_CMD);
    SPUtils::LoadCmd(killCmd + secondStr, str);
}

void StartUpDelay::GetHisysIdAndKill() const
{
    int time = 10;
    sleep(time);
    std::string str = "";
    std::string cmd = HISYSEVENT_CMD_MAP.at(HisyseventCmd::HISYS_PID);
    SPUtils::LoadCmd(cmd, str);
    std::stringstream ss(str);
    std::vector<std::string> hisysIdVec;
    std::string singleId;
    while (ss >> singleId) {
        hisysIdVec.push_back(singleId);
    }
    std::string killCmd = CMD_COMMAND_MAP.at(CmdCommand::KILL_CMD);
    for (size_t i = 0; i < hisysIdVec.size(); i++) {
        SPUtils::LoadCmd(killCmd + hisysIdVec[i], str);
    }
}
bool StartUpDelay::KillSpProcess() const
{
    std::string resultPid;
    std::string str;
    std::string cmd = CMD_COMMAND_MAP.at(CmdCommand::PIDOF_SP);
    SPUtils::LoadCmd(cmd, resultPid);
    std::vector<std::string> vec;
    std::string token;
    size_t pos = 0;
    while ((pos = resultPid.find(' ')) != std::string::npos) {
        token = resultPid.substr(0, pos);
        vec.push_back(token);
        resultPid.erase(0, pos + 1);
    }
    if (vec.size() > 0) {
        std::string killCmd = CMD_COMMAND_MAP.at(CmdCommand::KILL_CMD);
        for (size_t i = 0; i < vec.size(); i++) {
            SPUtils::LoadCmd(killCmd + vec[i], str);
        }
    }
    return false;
}

bool StartUpDelay::GetSpClear(bool isKillTestServer) const
{
    std::string curPid = std::to_string(getpid());
    FILE *fd = popen("ps -ef | grep -v grep | grep SP_daemon", "r");
    if (fd == nullptr) {
        return false;
    }
    char buf[4096] = {'\0'};
    while ((fgets(buf, sizeof(buf), fd)) != nullptr) {
        std::string line(buf);
        if (isKillTestServer || line.find("testserver") == std::string::npos) {
            KillTestSpdaemon(line, curPid);
        }
    }
    pclose(fd);
    return false;
}

void StartUpDelay::ClearOldServer() const
{
    std::string curPid = std::to_string(getpid());
    std::string commandServer = CMD_COMMAND_MAP.at(CmdCommand::SERVER_GREP);
    std::string resultPidServer;
    std::string commandEditorServer = CMD_COMMAND_MAP.at(CmdCommand::EDITOR_SERVER_GREP);
    std::string resultPidEditorServer;

    SPUtils::LoadCmdWithLinkBreak(commandServer, false, resultPidServer);
    SPUtils::LoadCmdWithLinkBreak(commandEditorServer, false, resultPidEditorServer);

    std::istringstream iss(resultPidServer + '\n' + resultPidEditorServer);
    std::string resultLine;
    std::string killResult;
    std::string killCmd = CMD_COMMAND_MAP.at(CmdCommand::KILL_CMD);
    while (std::getline(iss, resultLine)) {
        if (resultLine.empty() || resultLine.find("sh -c") != std::string::npos) {
            continue;
        }
        std::istringstream lineStream(resultLine);
        std::string token;

        int count = 0;
        while (lineStream >> token) {
            if (count == 1) {
                break;
            }
            count++;
        }
        if (token != curPid) {
            SPUtils::LoadCmd(killCmd + token, killResult);
            LOGD("Find old server: %s, killed.", token.c_str());
        }
    }
}

bool StartUpDelay::ExecuteCommand(const std::string& pkgName, std::string& output) const
{
    std::string command = "ps -ef | grep -v grep | grep " + pkgName;
    const std::vector<const char*> args = { "/bin/sh", "-c", command.c_str(), nullptr };
    int pipefd[2];
    pid_t pid;
    if (pipe(pipefd) == -1) {
        LOGE("StartUpDelay::Failed to create pipe");
        return false;
    }
    pid = fork();
    if (pid == -1) {
        LOGE("StartUpDelay::Failed to fork");
        return false;
    }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execvp(args[0], const_cast<char *const*>(args.data()));
        LOGE("StartUpDelay::Failed to execute ps ef");
        _exit(1);
    } else {
        close(pipefd[1]);
        char buffer[MAX_CHAR_SIZE];
        ssize_t bytesRead;
        while ((bytesRead = read(pipefd[0], buffer, sizeof(buffer))) > 0) {
            output.append(buffer, bytesRead);
        }
        close(pipefd[0]);
        waitpid(pid, nullptr, 0);
    }
    return true;
}

std::string StartUpDelay::GetAppInforByPs(const std::string& curPkgName) const
{
    const std::string pkgName = SPUtils::EscapeShellArgs(curPkgName);
    bool isInvalidPkgName = SPUtils::IsInvalidPkgName(pkgName);
    if (!isInvalidPkgName) {
        return std::to_string(ErrorSpCode::INVALID_PKG_NAME);
    }
    std::string appProcessInfor;
    if (!ExecuteCommand(pkgName, appProcessInfor)) {
        return std::to_string(ErrorSpCode::FILE_OPEN_IS_NULL);
    }
    return appProcessInfor;
}

std::vector<std::vector<std::string>> StartUpDelay::GetAppProcInfor(const std::string& curPkgName)
{
    std::vector<std::vector<std::string>> resultAppProcInfor;
    const size_t mainProcessPose = 1;
    const std::string eachRowOfData = GetAppInforByPs(curPkgName);
    if (eachRowOfData.empty()) {
        return {{std::to_string(ErrorSpCode::DATA_IS_EMPTY), "Not data found for package"}};
    }
    std::istringstream iss(eachRowOfData);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find("SP_daemon") != std::string::npos) {
            continue;
        }
        std::vector<std::string> eachRowOfProceInfor;
        SPUtils::StrSplit(line, " ", eachRowOfProceInfor);
        for (const auto& procName : eachRowOfProceInfor) {
            if (procName == curPkgName) {
                mainProcessId_ = eachRowOfProceInfor[mainProcessPose];
                break;
            }
        }
        resultAppProcInfor.push_back(eachRowOfProceInfor);
    }
    return resultAppProcInfor;
}

std::string StartUpDelay::GetPidByPkg(const std::string &curPkgName, std::string* pids)
{
    std::vector<std::vector<std::string>> resultProceInfor = GetAppProcInfor(curPkgName);
    std::string resultChildProcId;
    g_pidParams.clear();
    const size_t indexOne = 1;
    for (size_t i = 0; i < resultProceInfor.size(); ++i) {
        g_pidParams.push_back(resultProceInfor[i][indexOne]);
        resultChildProcId += (" " + resultProceInfor[i][indexOne]);
    }
    if (!resultChildProcId.empty()) {
        const size_t firstNonSpace = resultChildProcId.find_first_not_of(" ");
        resultChildProcId = resultChildProcId.substr(firstNonSpace);
    }
    if (pids != nullptr) {
        *pids = resultChildProcId;
    }
    LOGD("GetPidByPkg: mainProcessId_ = (%s), pids = (%s)", mainProcessId_.c_str(),
        pids == nullptr ? resultChildProcId.c_str() : pids->c_str());
    return mainProcessId_;
}

std::vector<std::string> StartUpDelay::GetPidParams() const
{
    return g_pidParams;
}

void StartUpDelay::KillTestSpdaemon(const std::string &line, const std::string &curPid) const
{
    std::istringstream iss(line);
    std::string cmd = "";
    std::string field;
    std::string cmdResult;
    std::string pid = "-1";
    int count = 0;
    int first = 1;
    while (iss >> field) {
        if (count == first) {
            pid = field;
            break;
        }
        count++;
    }
    if (pid != curPid) {
        cmd = "kill " + pid;
        SPUtils::LoadCmd(cmd, cmdResult);
    }
}
}
}
