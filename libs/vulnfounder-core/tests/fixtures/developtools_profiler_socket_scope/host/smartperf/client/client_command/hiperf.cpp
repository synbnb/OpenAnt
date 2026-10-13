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
#include <fstream>
#include <string>
#include <iostream>
#include <cctype>
#include "include/hiperf.h"
#include "include/sp_log.h"
#include "include/sp_thread_socket.h"
namespace OHOS {
namespace SmartPerf {
std::map<std::string, std::string> Hiperf::ItemData()
{
    std::map<std::string, std::string> result;
    LOGI("Hiperf:ItemData map size(%u)", result.size());
    return result;
}

void Hiperf::StartExecutionOnce(bool isPause)
{
    PrepareHiperf();
    StartHiperf();
}

void Hiperf::FinishtExecutionOnce(bool isPause)
{
    std::unique_lock<std::mutex> lock(hiperfLock_);
    StopHiperf();
    GetHiperfData();
}

void Hiperf::SetProcessId(const std::string &pid)
{
    processId_ = pid;
}

void Hiperf::PrepareHiperf()
{
    std::string cmdResult;
    const std::string preparedCmd = "hiperf stat --control prepare -p " + processId_ + " -o " + savePath_;
    SPUtils::LoadCmd(preparedCmd, cmdResult);
    if (cmdResult.empty()) {
        LOGE("create control hiperf sampling failed");
        return;
    }
    if (cmdResult.find("success") != std::string::npos) {
        LOGD("create control hiperf sampling success");
        return;
    }
    if (cmdResult.find("another sampling") != std::string::npos) {
        LOGD("control hiperf sampling is creatred");
        return;
    }
}

void Hiperf::StartHiperf()
{
    std::string cmdResult;
    const std::string startCmd = "hiperf stat --control start";
    SPUtils::LoadCmd(startCmd, cmdResult);
    if (cmdResult.empty()) {
        LOGE("hiperf start failed");
        return;
    }
    if (cmdResult.find("success") != std::string::npos) {
        LOGD("create control hiperf start success");
        return;
    }
}

void Hiperf::StopHiperf()
{
    std::string cmdResult;
    const std::string stopCmd = "hiperf stat --control stop";
    SPUtils::LoadCmd(stopCmd, cmdResult);
    if (cmdResult.empty()) {
        LOGE("hiperf stop failed");
        return;
    }
}

void Hiperf::GetHiperfData()
{
    std::string cmdResult;
    char buf[1024] = {'\0'};
    const std::string getHiperfFileCmd = "cat " + savePath_;
    FILE *fd = popen(getHiperfFileCmd.c_str(), "r");
    if (fd == nullptr) {
        LOGE("cat hiperf test.txt failed");
        return;
    }
    while (fgets(buf, sizeof(buf), fd) != nullptr) {
        std::string line = buf;
        SetDataMap(line);
    }
    hiperfFirstCollect_ = false;
    if (pclose(fd) == -1) {
        LOGE("Error: Failed to close file");
        return;
    }
}

void Hiperf::SetDataMap(std::string &line)
{
    for (const auto &dataKey : collectNodes_) {
        if (line.find(dataKey) != std::string::npos) {
            std::string count;
            std::stringstream ss(line);
            ss >> count;
            count = ProcessCountData(count);
            if (!hiperfFirstCollect_) {
                long long newCount = SPUtilesTye::StringToSometype<long long>(hiperfData_[dataKey]) +
                    SPUtilesTye::StringToSometype<long long>(count);
                hiperfData_[dataKey] = std::to_string(newCount);
            } else {
                hiperfData_[dataKey] = count;
            }
        }
    }
}

std::string Hiperf::ReturnHiperfData()
{
    std::string hiperfStr = "hci$$" + SpThreadSocket::GetInstance().MapToString(hiperfData_);
    LOGD("Hiperf::hiperfStr = %s", hiperfStr.c_str());
    return hiperfStr;
}

std::string Hiperf::ProcessCountData(std::string count)
{
    std::string countStr = "";
    for (char c : count) {
        if (!std::ispunct(c)) {
            countStr += c;
        }
    }
    return countStr;
}
}
}
