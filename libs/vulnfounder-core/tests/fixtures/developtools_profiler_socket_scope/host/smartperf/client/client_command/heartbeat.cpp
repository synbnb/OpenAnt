/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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

#include <iostream>
#include <chrono>
#include <cstdlib>
#include <unistd.h>
#include <mutex>
#include "include/heartbeat.h"
#include "include/sp_utils.h"
#include "sp_log.h"
#include "include/startup_delay.h"
#include "include/common.h"
namespace OHOS {
namespace SmartPerf {
void Heartbeat::KillSpId()
{
    std::string str;
    std::string resultPid;
    std::string cmd = CMD_COMMAND_MAP.at(CmdCommand::PIDOF_SP);
    SPUtils::LoadCmd(cmd, resultPid);
    std::vector<std::string> vec;
    std::string token;
    size_t pos = resultPid.find(' ');
    do {
        token = resultPid.substr(0, pos);
        vec.push_back(token);
        resultPid.erase(0, pos + 1);
    } while ((pos = resultPid.find(' ')) != std::string::npos);
    if (vec.size() > 0) {
        std::string killCmd = CMD_COMMAND_MAP.at(CmdCommand::KILL_CMD);
        for (size_t i = 0; i < vec.size(); i++) {
            SPUtils::LoadCmd(killCmd + vec[i], str);
        }
    }
}

void Heartbeat::HeartbeatRule()
{
    while (isrunning) {
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - updateStart).count();
        if (duration > timeout) {
            LOGD("Socket disconnected!");
            KillSpId();
        }
        sleep(checkMessageTime);
    }
}

void Heartbeat::UpdatestartTime()
{
    std::unique_lock<std::mutex> lock(mtx);
    updateStart = std::chrono::steady_clock::now();
}

}
}