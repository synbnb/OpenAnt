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

#ifndef SMARTPERF_COMMAND_H
#define SMARTPERF_COMMAND_H

#include <iostream>
#include <vector>
#include "common.h"
#include "sp_utils.h"
#include "GpuCounter.h"
#include "GameEvent.h"
#include "task_manager.h"

namespace OHOS {
namespace SmartPerf {
class SmartPerfCommand {
public:
    const std::string smartPerfExeName = "SP_daemon";
    const std::string smartPerfMsgErr = "error input!\n use command '--help' get more information\n";
    const std::string smartPerfMsg = "OpenHarmony performance testing tool SmartPerf command-line version\n"
        "Usage: SP_daemon [options] [arguments]\n\n"
        "options:\n"
        " -N              set the collection times(default value is 0) range[1,2147483647], for example: -N 10 \n"
        " -PKG            set package name, must add, for example: -PKG ohos.samples.ecg \n"
        " -PID            set process pid, must add, for example: -PID 3568 \n"
        " -threads        get threads, must add -PID or -PKG for example: \n"
                          "\t\t -threads -PID 3568 or -threads -PKG ohos.samples.ecg \n"
        " -c              get device CPU frequency and CPU usage, process CPU usage and CPU load .. \n"
        " -ci             get cpu instructions and cycles \n"
        " -g              get device GPU frequency and GPU load  \n"
        " -gc             get gpu counter default frequency is 50 \n"
        " -f              get app refresh fps(frames per second) and fps jitters and refreshrate \n"
        " -profilerfps    get refresh fps and timestamp \n"
        " -sections       set collection time period(using with profilerfps)\n"
        " -t              get remaining battery power and temperature.. \n"
        " -p              get battery power consumption and voltage(Not supported by some devices) \n"
        " -print          start mode print log \n"
        " -r              get process memory and total memory \n"
        " -snapshot       get screen capture\n"
        " -nav            get page navigation information\n"
        " -net            get uplink and downlink traffic\n"
        " -start          collection start command \n"
        " -stop           collection stop command \n"
        " -VIEW           set layler, for example: -VIEW DisplayNode \n"
        " -OUT            set csv output path.\n"
        " -d              get device DDR information \n"
        " -screen         get screen resolution \n"
        " -deviceinfo     get device information \n"
        " -server         start a process to listen to the socket message of the start and stop commands \n"
        " -clear          clear the process ID \n"
        " -ohtestfps      used by the vilidator to obtain the fps, the collection times can be set \n"
        " -editorServer:xxx   start a process to listen to the socket message of the editor \n"
        " -deviceServer:xxx   start a process to listen to the socket message of the device \n"
        " -recordcapacity get the battery level difference \n"
        " --version       get version \n"
        " --help          get help \n"
        " -editor         scenario-based collection identifier, parameter configuration items can be added later \n"
        " responseTime   get the page response delay after an application is operated \n"
        " completeTime   get the page completion delay after an application is operated \n"
        " fpsohtest      used by the vilidator to obtain the fps \n"
        "example1:\n"
        "SP_daemon -N 20 -c -g -t -p -r -net -snapshot -d \n"
        "SP_daemon -N 20 -PKG ohos.samples.ecg -c -g -t -p -f -r -net -snapshot -d -nav -gc \n"
        "SP_daemon -start -c \n"
        "SP_daemon -stop \n"
        "example2: These parameters need to be used separately \n"
        "SP_daemon -screen \n"
        "SP_daemon -deviceinfo \n"
        "SP_daemon -server \n"
        "SP_daemon -clear \n"
        "SP_daemon -ohtestfps 10 \n"
        "SP_daemon -recordcapacity \n"
        "example3: These parameters need to be used separately \n"
        "SP_daemon -editor responseTime ohos.samples.ecg app name \n"
        "SP_daemon -editor completeTime ohos.samples.ecg app name \n"
        "SP_daemon -editor fpsohtest \n";

    const size_t oneParam = 1;
    const size_t twoParam = 2;
    const size_t threeParamMore = 3;
    const size_t serverCommandLength = 14;  // -deviceServer: 与 -editorServer: 的长度
    explicit SmartPerfCommand(std::vector<std::string>& argv);
    ~SmartPerfCommand() {};
    static void InitSomething();
    std::string ExecCommand();
    void HelpCommand(CommandHelp type, const std::string& token) const;
    void CreateSocketThread() const;
    void DeviceServer(int isNeedDaemon) const;
    TaskManager taskMgr_;
};
}
}
#endif // SMARTPERF_COMMAND_H