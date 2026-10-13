/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <ctime>
#include <sys/time.h>
#include "include/sp_utils.h"
#include "include/jitters.h"
#include "include/startup_delay.h"
#include "include/sp_log.h"
#include "include/common.h"
#include <sys/wait.h>
#include <sys/types.h>
namespace OHOS {
namespace SmartPerf {
std::map<std::string, std::string> Jitters::ItemData()
{
    std::map<std::string, std::string> result;
    jittersInfo.currDumpTimeStamps.clear();
    if (pkgName.empty() || processId.empty()) {
        result["fpsJitters"] = "NA";
    } else if (!pkgName.empty() && processId.empty()) {
        result["fpsJitters"] = "";
    } else {
        JittersInfo jittersInfoResult = GetJittersInfo();
        prevResultFpsInfo = jittersInfoResult;
        std::string jitterStr = "";
        std::string split = "";
        for (size_t i = 0; i < jittersInfoResult.jitters.size(); i++) {
            if (i > 0) {
                split = ";;";
            }
            jitterStr += split + std::to_string(jittersInfoResult.jitters[i]);
        };
        result["fpsJitters"] = jitterStr;
        LOGD("result.fps: %s, result.curTime: %s, result.jitters: %s",
            std::to_string(jittersInfoResult.fps).c_str(),
            std::to_string(jittersInfoResult.curTime).c_str(),
            jitterStr.c_str());
    }
    return result;
}

void Jitters::StartExecutionOnce(bool isPause)
{
    if (isPause) {
        return;
    }
    isGameApp = SPUtils::GetIsGameApp(pkgName);
}

void Jitters::SetPackageName(const std::string& pName)
{
    pkgName = pName;
}

void Jitters::SetProcessId(const std::string &pid)
{
    processId = pid;
}

JittersInfo Jitters::GetJittersInfo()
{
    std::string uniteLayer = "composer";
    bool onTop = OHOS::SmartPerf::SPUtils::IsForeGround(pkgName);
    if (onTop) {
        OHOS::SmartPerf::SPUtils::GetCurrentTime(prevResultFpsInfo.curTime);
        jittersInfoData = GetJittersByDump(uniteLayer);
    } else {
        jittersInfoData.jitters.clear();
    }
    return jittersInfoData;
}

JittersInfo Jitters::GetJittersByDump(const std::string& name)
{
    JittersInfo tmpFps;
    tmpFps.fps = 0;
    tmpFps.jitters.clear();
    jittersInfo = tmpFps;
    bool isBreak = false;
    std::string commond = "fps " + name;
    const std::string cmd = "hidumper -s 10 -a \"" + commond + "\"";
    FILE *fp = popen(cmd.c_str(), "r");
    if (fp == nullptr) {
        LOGE("Failed to open hidumper file");
        return jittersInfo;
    }
    fpsNum = 0;
    prevScreenTimestamp = -1;
    struct timespec sysTime = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &sysTime);
    jittersInfo.curTime = static_cast<int>(sysTime.tv_sec - 1);
    LOGD("jittersInfo.curTime: (%d)", jittersInfo.curTime);
    char tmp[1024];
    std::stringstream sstream;
    while (fgets(tmp, sizeof(tmp), fp) != nullptr) {
        LOGD("jittersInfo::dump time: %s", tmp);
        std::string tmpStr(tmp);
        curScreenTimestamp = 0;
        sstream.clear();
        sstream.str(tmpStr);
        sstream >> curScreenTimestamp;
        if (curScreenTimestamp == 0) {
            continue;
        }
        if (CalcFpsAndJitters(isBreak)) {
            break;
        }
    }
    CalcJitters();
    if (pclose(fp) == -1) {
        LOGE("Error::Failed to close file");
        return jittersInfo;
    }
    return jittersInfo;
}

bool Jitters::CalcFpsAndJitters(bool isBreak)
{
    long long onScreenTime = curScreenTimestamp / mod;
    bool findFpsCurTime = (onScreenTime == jittersInfo.curTime);
    if (findFpsCurTime) {
        isBreak = true;
        fpsNum++;
        jittersInfo.fps = fpsNum;
        jittersInfo.currDumpTimeStamps.push_back(curScreenTimestamp);
    } else {
        findFpsCurTime = false;
    }
    return isBreak && !findFpsCurTime;
}

void Jitters::CalcJitters()
{
    bool isOrder = true;
    if (jittersInfo.currDumpTimeStamps.size() > 1) {
        isOrder = jittersInfo.currDumpTimeStamps[1] - jittersInfo.currDumpTimeStamps[0] > 0;
    }
    if (isOrder) {
        for (size_t i = 0; i < jittersInfo.currDumpTimeStamps.size(); i++) {
            curScreenTimestamp = jittersInfo.currDumpTimeStamps[i];
            jittersInfo.currTimeStamps.push_back(curScreenTimestamp);
            long long jitter = CalculateJitter();
            jittersInfo.jitters.push_back(jitter);
            prevlastScreenTimestamp = curScreenTimestamp;
            prevScreenTimestamp = curScreenTimestamp;
        }
    } else {
        for (size_t i = jittersInfo.currDumpTimeStamps.size(); i > 0; i--) {
            curScreenTimestamp = jittersInfo.currDumpTimeStamps[i - 1];
            jittersInfo.currTimeStamps.push_back(curScreenTimestamp);
            long long jitter = CalculateJitter();
            jittersInfo.jitters.push_back(jitter);
            prevlastScreenTimestamp = curScreenTimestamp;
            prevScreenTimestamp = curScreenTimestamp;
        }
    }
    if (!jittersInfo.jitters.empty()) {
        jittersInfo.jitters.erase(jittersInfo.jitters.begin());
    }
}

long long Jitters::CalculateJitter() const
{
    long long jitter;
    if (prevScreenTimestamp == -1) {
        if (prevlastScreenTimestamp != 0 && (curScreenTimestamp - prevlastScreenTimestamp) < mod) {
            jitter = curScreenTimestamp - prevlastScreenTimestamp;
        } else {
            jitter = curScreenTimestamp % mod;
        }
    } else {
        jitter = curScreenTimestamp - prevScreenTimestamp;
    }
    return jitter;
}
}
}