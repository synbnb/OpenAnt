/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
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
#include "include/Network.h"
#include <sstream>
#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>
#include <dirent.h>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <climits>
#include <cctype>
#include <thread>
#include "sys/time.h"
#include "securec.h"
#include "include/sp_utils.h"
#include "include/Dubai.h"
#include "include/sp_log.h"
const int LARGE_BUFF_MAX_LEN = 256;
namespace OHOS {
namespace SmartPerf {
std::map<std::string, std::string> Network::ItemData()
{
    if (hapFlag) {
        ThreadFunctions();
    } else {
        result = Network::GetNetworkInfo();
    }
    LOGI("Network:ItemData map size(%u)", result.size());
    return result;
}

std::map<std::string, std::string> Network::GetNetworkInfo()
{
    std::map<std::string, std::string> networkInfo;
    networkInfo = GetNetworkInfoDev();
    if (isFirst) {
        networkInfo["networkUp"] = "0";
        networkInfo["networkDown"] = "0";
        isFirst = false;
        diffRx = 0;
        diffTx = 0;
        return networkInfo;
    }
    networkInfo["networkUp"] = std::to_string(diffTx);
    networkInfo["networkDown"] = std::to_string(diffRx);
    if (!hapFlag || stophapFlag) {
        diffTx = 0;
        diffRx = 0;
    }
    return networkInfo;
}
std::map<std::string, std::string> Network::GetNetworkInfoDev()
{
    std::map<std::string, std::string> networkInfo;
    char buff[LARGE_BUFF_MAX_LEN];
    FILE *fp = fopen("/proc/net/dev", "r");
    if (fp == nullptr) {
        std::cout << "net work node is not accessed" << std::endl;
        return networkInfo;
    }
    while (fgets(buff, LARGE_BUFF_MAX_LEN, fp) != nullptr) {
        if (strstr(buff, "rmnet0") && PerciseMatch(buff, "mnet0")) {
            if (sscanf_s(buff, "%*s%lld%*lld%*lld%*lld%*lld%*lld%*lld%*lld%lld%*lld%*lld%*lld%*lld%*lld%*lld%*lld",
                &curRx, &curTx) < 0) {
                (void)fclose(fp);
                return networkInfo;
            }
            GetCurNetwork(rmnetCurRx, rmnetCurTx);
        }
        if (strstr(buff, "eth0") && PerciseMatch(buff, "eth0")) {
            if (sscanf_s(buff, "%*s%lld%*lld%*lld%*lld%*lld%*lld%*lld%*lld%lld%*lld%*lld%*lld%*lld%*lld%*lld%*lld",
                &curRx, &curTx) < 0) {
                (void)fclose(fp);
                return networkInfo;
            }
            GetCurNetwork(ethCurRx, ethCurTx);
        }
        if (strstr(buff, "wlan0") && PerciseMatch(buff, "wlan0")) {
            if (sscanf_s(buff, "%*s%lld%*lld%*lld%*lld%*lld%*lld%*lld%*lld%lld%*lld%*lld%*lld%*lld%*lld%*lld%*lld",
                &curRx, &curTx) < 0) {
                (void)fclose(fp);
                return networkInfo;
            }
            GetCurNetwork(wlanCurRx, wlanCurTx);
        }
    }
    (void)fclose(fp);
    return networkInfo;
}
void Network::GetCurNetwork(long long &networkCurRx, long long &networkCurTx)
{
    if (curRx > 0) {
        allRx = curRx - networkCurRx;
    }
    networkCurRx = curRx;
    if (curTx > 0) {
        allTx = curTx - networkCurTx;
    }
    networkCurTx = curTx;
    if (allRx >= 0) {
        diffRx += allRx;
    } else {
        diffRx += networkCurRx;
    }
    if (allTx >= 0) {
        diffTx += allTx;
    } else {
        diffTx += networkCurTx;
    }
    curRx = 0;
    curTx = 0;
    allRx = 0;
    allTx = 0;
}
void Network::IsFindHap()
{
    hapFlag = true;
    ClearHapFlag();
}
void Network::IsStopFindHap()
{
    hapFlag = false;
    stophapFlag = true;
}

void Network::ThreadFunctions()
{
    auto threadGetHapNetwork = std::thread([this]() { this->ThreadGetHapNetwork(); });
    threadGetHapNetwork.detach();
}

void Network::ThreadGetHapNetwork()
{
    while (!stophapFlag) {
        long long startTime = SPUtils::GetCurTime();
        result = GetNetworkInfo();
        std::string hapPid = "";
        const std::string cmd = "pidof " + Dubai::dubaiPkgName;
        SPUtils::LoadCmd(cmd, hapPid);
        if (!hapPid.empty()) {
            long long stopTime = SPUtils::GetCurTime();
            long long time = 998;
            long long costTime = stopTime - startTime;
            std::this_thread::sleep_for(std::chrono::milliseconds(time - costTime));
        } else {
            break;
        }
    }
}
void Network::ClearHapFlag()
{
    isFirst = true;
    stophapFlag = false;
    rmnetCurRx = 0;
    rmnetCurTx = 0;
    ethCurRx = 0;
    ethCurTx = 0;
    wlanCurRx = 0;
    wlanCurTx = 0;
}

bool Network::PerciseMatch(const char *buff, const std::string &netStr)
{
    std::string line(buff);
    bool matchFlag = false;
    size_t colonPos = line.find(':');
    if (colonPos != std::string::npos) {
        std::string interFace = line.substr(1, colonPos - 1);
        if (strcmp(interFace.c_str(), netStr.c_str()) == 0) {
            matchFlag = true;
        }
    }
    return matchFlag;
}
}
}
