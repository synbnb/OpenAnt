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
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <cstring>
#include <iterator>
#include "include/GameEvent.h"
#include "unistd.h"
#include "include/heartbeat.h"
#include "include/sp_utils.h"
#include "include/sp_csv_util.h"
#include "include/sp_profiler_factory.h"
#include "include/sp_thread_socket.h"
#include "include/startup_delay.h"
#include "include/ByTrace.h"
#include "include/smartperf_command.h"
#include "include/sp_log.h"
#include "include/RAM.h"
#include "include/common.h"
#include "include/FPS.h"
#include "include/sp_task.h"
#include "cpu_info.h"
#include "AI_schedule.h"

namespace OHOS {
namespace SmartPerf {
SmartPerfCommand::SmartPerfCommand(std::vector<std::string>& argv)
{
    taskMgr_.AddTask(argv);
    LOGD("SmartPerfCommand::SmartPerfCommand size(%u)", argv.size());
    if (argv.size() == oneParam) {
        SPUtils::KillStartDaemon();
        SpThreadSocket::GetInstance().SetNeedUdpToken(false);
        DeviceServer(true);
    }
    if (argv.size() == twoParam) {
        auto iterator = COMMAND_HELP_MAP.begin();
        while (iterator != COMMAND_HELP_MAP.end()) {
            if (iterator->second.compare(argv[1]) == 0) {
                HelpCommand(iterator->first, "");
                break;
            }
            if (argv[1].find("-editorServer") != std::string::npos) {
                WLOGI("############################# Found '-editorServer' argument in argv");
                std::string token = argv[1].substr(serverCommandLength, argv[1].length() - serverCommandLength);
                SPUtils::KillStartDaemon();
                HelpCommand(CommandHelp::EDITORSERVER, token);
            } else if (argv[1].find("-deviceServer") != std::string::npos) {
                WLOGI("############################# Found '-deviceServer' argument in argv");
                std::string token = argv[1].substr(serverCommandLength, argv[1].length() - serverCommandLength);
                HelpCommand(CommandHelp::DEVICESERVER, token);
            }
            ++iterator;
        }
    }
    LOGD("SmartPerfCommand::SmartPerfCommand complete");
}
void SmartPerfCommand::DeviceServer(int isNeedDaemon) const
{
    EnableWriteLogAndDeleteOldLogFiles();
    OHOS::SmartPerf::StartUpDelay sd;
    sd.KillSpProcess();
    std::string pidStr = "";
    std::string result = "";
    std::string cmdStr = CMD_COMMAND_MAP.at(CmdCommand::PIDOF_SP);
    SPUtils::LoadCmd(cmdStr, pidStr);
    cmdStr = CMD_COMMAND_MAP.at(CmdCommand::TASKSET);
    SPUtils::LoadCmd(cmdStr + pidStr, result);
    if (isNeedDaemon) {
        daemon(0, 0);
    }
    CreateSocketThread();
}

void SmartPerfCommand::HelpCommand(CommandHelp type, const std::string& token) const
{
    if (type == CommandHelp::HELP) {
        std::cout << smartPerfMsg << std::endl;
    }
    if (type == CommandHelp::VERSION) {
        std::cout << "Version: " << SPUtils::GetVersion() << std::endl;
    }
    if (type == CommandHelp::SCREEN) {
        std::string result = SPUtils::GetScreen();
        std::cout << result << std::endl;
    }
    OHOS::SmartPerf::StartUpDelay sd;
    if (type == CommandHelp::CLEAR || type == CommandHelp::CLEARALL) {
        bool isClearTestServer = (type == CommandHelp::CLEARALL);
        sd.GetSpClear(isClearTestServer);
    }
    if (type == CommandHelp::SERVER || type == CommandHelp::EDITORSERVER) {
        sd.ClearOldServer();
        SPUtils::GetTtyDeviceFd();
        std::string pidStr = "";
        std::string result = "";
        std::string cmdStr = CMD_COMMAND_MAP.at(CmdCommand::PIDOF_SP);
        SPUtils::LoadCmd(cmdStr, pidStr);
        cmdStr = CMD_COMMAND_MAP.at(CmdCommand::TASKSET);
        SPUtils::LoadCmd(cmdStr + pidStr, result);
        if (type == CommandHelp::SERVER) {
            daemon(0, 0);
        } else {
            // Editor 拉起 daemon 测试
            EnableWriteLogAndDeleteOldLogFiles();
            if (token.empty()) {
                WLOGE("Error: token is empty when setting TCP token.");
                return;
            }
            SpThreadSocket::GetInstance().SetToken(token);
            WLOGI("############################# EditorServer Socket Create Start, Ready to Start Collector...");
        }
        CreateSocketThread();
    }
    if (type == CommandHelp::DEVICESERVER) {
        // device 拉起 daemon 测试
        if (token.empty()) {
            WLOGE("Error: token is empty when setting UDP token.");
            return;
        }
        SpThreadSocket::GetInstance().SetToken(token);
        DeviceServer(false);
        WLOGI("############################# DeviceServer Socket Create Start, Ready to Start Collector...");
    }
}

void SmartPerfCommand::CreateSocketThread() const
{
    InitSomething();
    auto tcpSocket = std::thread([]() { SpThreadSocket::GetInstance().Process(ProtoType::TCP); });
    sleep(1);
    auto udpSocket = std::thread([]() { SpThreadSocket::GetInstance().Process(ProtoType::UDP); });
    sleep(1);
    auto udpexSocket = std::thread([]() { SpThreadSocket::GetInstance().Process(ProtoType::UDPEX); });
    const char* noHeartbeat = getenv("SP_NO_HEARTBEAT");
    if (noHeartbeat != nullptr && strcmp(noHeartbeat, "1") == 0) {
        unsetenv("SP_NO_HEARTBEAT");
    } else {
        Heartbeat::GetInstance().UpdatestartTime();
        std::thread([]() { Heartbeat::GetInstance().HeartbeatRule(); }).detach();
    }
    tcpSocket.join();
    udpSocket.join();
    udpexSocket.join();
}

std::string SmartPerfCommand::ExecCommand()
{
    if (taskMgr_.GetArgumentParser().Get("-N") == std::nullopt) {
        return "command exec finished!";
    }
    RAM &ram = RAM::GetInstance();
    ram.SetFirstFlag();
    taskMgr_.DeleteTask(&AISchedule::GetInstance());
    taskMgr_.InitDataCsv();
    taskMgr_.Start();
    taskMgr_.Wait();
    taskMgr_.Stop();
    taskMgr_.WriteToCSV();
    return std::string("command exec finished!");
}

void SmartPerfCommand::InitSomething()
{
    std::string cmdResult;
    std::string stat = CMD_COMMAND_MAP.at(CmdCommand::PROC_STAT);
    if (SPUtils::LoadCmd(stat, cmdResult)) {
        LOGE("SmartPerfCommand::InitSomething Privilege escalation!");
    };
}
}
}
