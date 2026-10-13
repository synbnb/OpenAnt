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
#include "include/navigation.h"
#include <iostream>
#include "include/sp_utils.h"
#include "include/startup_delay.h"
#include "include/sp_log.h"
#include "include/common.h"

namespace OHOS {
namespace SmartPerf {
std::map<std::string, std::string> Navigation::ItemData()
{
    std::map<std::string, std::string> result = Navigation::GetNavInfo();
    LOGI("Navigation:ItemData map size(%u)", result.size());
    return result;
}

void Navigation::SetProcessId(const std::string &pid)
{
    processId = pid;
}

std::map<std::string, std::string> Navigation::GetNavInfo() const
{
    std::map<std::string, std::string> navInfo;
    std::string winId = "";
    winId = GetWinId(processId);
    if (winId != "-1") {
        navInfo = GetNavResult(winId);
    } else {
        navInfo["navPathName"] = "No Navigation Info";
    }
    return navInfo;
}

std::map<std::string, std::string> Navigation::GetNavResult(const std::string& winId) const
{
    std::map<std::string, std::string> navInfo;
    std::string nameStr = "No Navigation Info";
    std::string cmd = HIDUMPER_CMD_MAP.at(HidumperCmd::DUMPER_NAV) + winId + " -navigation'";
    if (cmd.empty()) {
        navInfo["navPathName"] = nameStr;
        return navInfo;
    }
    FILE *navfd = popen(cmd.c_str(), "r");
    if (navfd == nullptr) {
        navInfo["navPathName"] = nameStr;
        return navInfo;
    }
    char buf[4096] = {'\0'};
    while ((fgets(buf, sizeof(buf), navfd)) != nullptr) {
        std::string line(buf);
        SubstrNavName(line, nameStr);
    }
    if (pclose(navfd) == -1) {
        LOGE("Error: Failed to close file");
        navInfo["navPathName"] = nameStr;
        return navInfo;
    }
    navInfo["navPathName"] = nameStr;
    LOGD("navPathName = %s", nameStr.c_str());
    return navInfo;
}

void Navigation::SubstrNavName(const std::string &line, std::string &nameStr) const
{
    size_t nameShangPos = line.find("name: ");
    size_t nameTrunkPos = line.find("Name: ");
    size_t startPos = line.find("\"", nameTrunkPos + 6);
    size_t endPos = line.find("\"", startPos + 1);
    if (line.find("[0]") != std::string::npos) {
        if (nameTrunkPos != std::string::npos || nameShangPos != std::string::npos) {
            if (startPos != std::string::npos && endPos != std::string::npos) {
                nameStr = line.substr(startPos + 1, endPos - startPos - 1);
            }
        }
    }
}

std::string Navigation::GetWinId(std::string navPid) const
{
    std::string wid;
    const std::string cmd = HIDUMPER_CMD_MAP.at(HidumperCmd::DUMPER_A_A);
    FILE *fd = popen(cmd.c_str(), "r");
    if (fd == nullptr) {
        return wid = -1;
    }
    char buf[1024] = {'\0'};
    while ((fgets(buf, sizeof(buf), fd)) != nullptr) {
        std::string line = buf;
        if (line.find("---") != std::string::npos || line.length() <= 1 ||
            line.find("WindowName") != std::string::npos) {
            continue;
        }
        std::vector<std::string> params;
        SPUtils::StrSplit(line, " ", params);
        if (static_cast<int>(params.size()) > paramThree) {
            if (params[paramTwo] == navPid) {
                wid = params[paramThree];
                break;
            }
        }
    }
    if (pclose(fd) == -1) {
        LOGE("Error: Failed to close file");
        return wid = -1;
    }
    return wid;
}
}
}
