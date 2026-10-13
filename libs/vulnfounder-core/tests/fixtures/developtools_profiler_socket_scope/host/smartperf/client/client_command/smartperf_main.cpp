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
#include <cstring>
#include <cstdlib>
#include "unistd.h"
#include <fstream>
#include <sstream>
#include "include/smartperf_command.h"
#include "include/editor_command.h"
#include "include/FPS.h"
#include "include/client_control.h"
#include "include/sp_utils.h"
#include "include/sp_log.h"
#include "include/common.h"
#include "parameters.h"
#include "task_manager.h"
#include "include/startup_delay.h"

constexpr const char *VERSION_TYPE = "const.logsystem.versiontype";
static std::string GetOptions(const std::vector<std::string> &argv)
{
    std::string str = "";
    std::string strFlag;
    bool isFill = false;
    for (std::size_t i = 0; i < argv.size(); i++) {
        if (!isFill) {
            strFlag = argv[i];
            if (strFlag.find("SP_daemon") != std::string::npos) {
                isFill = true;
            }
        } else {
            str += argv[i];
            if (i + 1 != argv.size()) {
                str += " ";
            }
        }
    }
    return str;
}
static void KeyInsert(std::set<std::string> &keysMap)
{
    keysMap.insert("editor");
    keysMap.insert("profilerfps");
    keysMap.insert("start");
    keysMap.insert("stop");
    keysMap.insert("screen");
    keysMap.insert("clear");
    keysMap.insert("clearAll");
    keysMap.insert("server");
    keysMap.insert("sections");
    keysMap.insert("deviceinfo");
    keysMap.insert("ohtestfps");
    keysMap.insert("editorServer");
    keysMap.insert("deviceServer");
    keysMap.insert("recordcapacity");
}
static bool g_checkCmdParam(std::vector<std::string> &argv, std::string &errorInfo)
{
    std::string str = GetOptions(argv);
    std::set<std::string> keys; // Includes three parts "SP_daemon" CommandType and CommandHelp
    if (str.empty()) {
        return true;
    }
    // 'help' and 'version' start with "--" and are processed separately
    if (str.find("--help") != std::string::npos || str.find("--version") != std::string::npos) {
        std::vector<std::string> out;
        OHOS::SmartPerf::SPUtils::StrSplit(str, "-", out);
        if (out.size() != 1) {
            errorInfo = "--help and --version cannot be used together with other options";
            return false;
        } else {
            return true;
        }
    }
    if (str.find("-PKG") != std::string::npos && str.find("-PID") != std::string::npos) {
        errorInfo = "-PKG and -PID cannot be used together with";
        return false;
    }
    KeyInsert(keys);
    // editor 与 device 的拉起命令与 token 一起加入白名单
    if (argv[1].find("editorServer:") != std::string::npos ||
        argv[1].find("deviceServer:") != std::string::npos
    ) {
        keys.insert(argv[1].substr(1).c_str());
    }
    for (auto& a : OHOS::SmartPerf::COMMAND_SHELL_MAP) {
        keys.insert(a.first.substr(1)); // No prefix required '-'
    }

    /* ************The command line for the following parameters is not implemented****************** */
    keys.erase("f1");
    keys.erase("f2");
    keys.erase("fl");
    keys.erase("ftl");
    keys.erase("editorServer");
    keys.erase("deviceServer");
    return OHOS::SmartPerf::SPUtils::VeriyParameter(keys, str, errorInfo);
}

static void SocketStopCommand()
{
    OHOS::SmartPerf::ClientControl cc;
    cc.SocketStop();
}

static void SocketStartCommand(int argc, char *argv[])
{
    setenv("SP_NO_HEARTBEAT", "1", 1);
    OHOS::SmartPerf::SPUtils::KillStartDaemon();
    std::string startStr = "";
    std::string endStr = "";
    std::string pidCmd = OHOS::SmartPerf::CMD_COMMAND_MAP.at(OHOS::SmartPerf::CmdCommand::PIDOF_SP);
    OHOS::SmartPerf::SPUtils::LoadCmd(pidCmd, startStr);
    OHOS::SmartPerf::ClientControl cc;
    cc.StartSPDaemon();
    unsetenv("SP_NO_HEARTBEAT");
    OHOS::SmartPerf::SPUtils::LoadCmd(pidCmd, endStr);
    std::vector<std::string> startParams;
    std::vector<std::string> endParams;
    OHOS::SmartPerf::SPUtils::StrSplit(startStr, " ", startParams);
    OHOS::SmartPerf::SPUtils::StrSplit(endStr, " ", endParams);
    std::string result;
    const int maxExpectedArgs = 100;
    for (int i = 2; i < argc && i < maxExpectedArgs; i++) {
        result += argv[i];
        if (i != argc - 1) {
            result += " ";
        }
    }
    if (startParams.size() == endParams.size()) {
        std::cout << "The last collection is interrupted." << std::endl;
        std::cout << "SP_daemon -start " << result << " started collecting..." << std::endl;
    }
    cc.SocketStart(result);
}

static void RecordCapacity()
{
    const std::string capacityRmPath = "/sys/class/power_supply/Battery/capacity_rm";
    const std::string rkCapacityRmPath = "/data/service/el0/battery/battery/capacity";
    const std::string capacitySavePath = "/data/local/tmp/powerLeftRecord.csv";
    std::string capacityString;
    std::ifstream infile(capacitySavePath.c_str());
    if (infile.is_open()) {
        std::stringstream buffer;
        int capacityLine = 0;
        std::string line;
        const int MAX_RECORD_COUNT = 100;
        buffer << infile.rdbuf();
        capacityString = buffer.str();
        infile.close();

        while (std::getline(buffer, line)) {
            capacityLine++;
        }
        if (capacityLine == MAX_RECORD_COUNT) {
            std::size_t pos = capacityString.find('\n');
            if (pos != std::string::npos) {
                capacityString = capacityString.substr(pos + 1);
            }
        }
    }
    std::ofstream outFile(capacitySavePath.c_str(), std::ios::out | std::ios::trunc);
    if (!outFile.is_open()) {
        std::cout << "Error opening capacity file!" << std::endl;
        return;
    }
    std::string recordPower;
    auto recordTime = std::to_string(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    OHOS::SmartPerf::SPUtils::LoadFile(capacityRmPath, recordPower);
    if (recordPower.empty()) {
        std::string rkRecordPower;
        int maxBat = 60;
        OHOS::SmartPerf::SPUtils::LoadFile(rkCapacityRmPath, rkRecordPower);
        recordPower = std::to_string(OHOS::SmartPerf::SPUtilesTye::StringToSometype<int>(rkRecordPower) * maxBat);
    }
    std::cout << "recordTime: " << recordTime << std::endl << "recordPower: " << recordPower << std::endl;
    capacityString += recordTime + "," + recordPower;
    outFile << capacityString << std::endl;
    if (outFile.fail()) {
        const int bufSize = 256;
        char buf[bufSize] = { 0 };
        std::cout << "Error writing capacity failed:" << strerror_r(errno, buf, bufSize) << std::endl;
    }
    outFile.close();
}

static int ProcessSpecificParameter(int argc, char *argv[], std::vector<std::string> &vec)
{
    if (argc > 1 && strcmp(argv[1], "-editor") == 0) {
        OHOS::SmartPerf::EditorCommand(argc, vec);
        return 0;
    } else if (argc > 1 && strcmp(argv[1], "-profilerfps") == 0) {
        OHOS::SmartPerf::FPS::GetInstance().GetFPS(vec);
        return 0;
    } else if (argc > 1 && strcmp(argv[1], "-start") == 0) {
        SocketStartCommand(argc, argv);
        std::cout << "command exec finished!" << std::endl;
        return 0;
    } else if (argc > 1 && strcmp(argv[1], "-stop") == 0) {
        SocketStopCommand();
        std::cout << "command exec finished!" << std::endl;
        return 0;
    } else if (argc > 1 && strcmp(argv[1], "-deviceinfo") == 0) {
        std::cout << OHOS::SmartPerf::SPUtils::GetDeviceInfoMap() << std::endl;
        return 0;
    } else if (argc > 1 && strcmp(argv[1], "-ohtestfps") == 0) {
        OHOS::SmartPerf::FPS::GetInstance().GetOhFps(vec);
        return 0;
    } else if (argc > 1 && strcmp(argv[1], "-recordcapacity") == 0) {
        RecordCapacity();
        return 0;
    }
    return 1;
}

int main(int argc, char *argv[])
{
    if (OHOS::system::GetParameter(VERSION_TYPE, "Unknown") != "beta") {
        if (!OHOS::system::GetBoolParameter("const.security.developermode.state", true)) {
            std::cout << "Not a development mode state" << std::endl;
            return 0;
        }
    }
    const int maxExpectedArgs = 100;
    std::string errorInfo;
    std::vector<std::string> vec;
    if (argc < 0 || argc > maxExpectedArgs) {
        std::cout << "Invalid argument count" << std::endl;
        return -1;
    }
    for (int i = 0; i < argc; i++) {
        vec.push_back(argv[i]);
    }
    if (!g_checkCmdParam(vec, errorInfo)) {
        std::cout << "SP_daemon:" << errorInfo << std::endl <<
             "Usage: SP_daemon [options] [arguments]" << std::endl << std::endl <<
             "Try `SP_daemon --help' for more options." << std::endl;
        return 0;
    }
    OHOS::SmartPerf::SPUtils::SetRkFlag();
    if (ProcessSpecificParameter(argc, argv, vec) == 0) {
        return 0;
    }

    OHOS::SmartPerf::SmartPerfCommand cmd(vec);
    OHOS::SmartPerf::StartUpDelay sd;
    sd.KillSpProcess();
    std::cout << cmd.ExecCommand() << std::endl;
    return 0;
}
