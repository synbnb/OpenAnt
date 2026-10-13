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
#include <iostream>
#include <sstream>
#include <filesystem>
#include <thread>
#include "unistd.h"
#include "include/sp_utils.h"
#include "include/ByTrace.h"
#include "include/sp_log.h"
#include "include/common.h"

namespace {
constexpr long long TIME_DIFF_THRESHOLD = 10000;
}
namespace OHOS {
namespace SmartPerf {
std::map<std::string, std::string> ByTrace::ItemData()
{
    return std::map<std::string, std::string>();
}

long long ByTrace::GetThreshold() const
{
    long long jitters = jitterTimesTaken;
    return jitters;
}

int ByTrace::GetLowFps() const
{
    int lowfps = lowFps;
    return lowfps;
}

void ByTrace::SetByTrace()
{
    std::vector<std::string> values;
    std::string delimiter = "||";
    std::string delim = "=";
    size_t boundSize = 2;
    SPUtils::StrSplit(jittersAndLowFps, delimiter, values);
    bool jitterTimesTakenSet = false;
    bool lowFpsSet = false;
    for (std::string& vItem : values) {
        std::vector<std::string> vItems;
        SPUtils::StrSplit(vItem, delim, vItems);
        if (vItems.size() >= boundSize) {
            if (vItems[0] == "fpsJitterTime") {
                jitterTimesTaken = SPUtilesTye::StringToSometype<int>(vItems[1]);
                jitterTimesTakenSet = true;
            }
            if (vItems[0] == "lowFps") {
                lowFps = SPUtilesTye::StringToSometype<int>(vItems[1]);
                lowFpsSet = true;
            }
        }
    }
    if (!jitterTimesTakenSet || !lowFpsSet) {
        LOGE("ByTrace::Missing required parameters in jittersAndLowFps");
        return;
    }
    LOGD("ByTrace::SetByTrace jitterTimesTaken(%lld), lowFps(%d)", jitterTimesTaken, lowFps);
}

void ByTrace::ClearTraceFiles() const
{
    if (std::filesystem::exists(traceCpPath_)) {
        RemoveTraceFiles();
    }
}

void ByTrace::RemoveTraceFiles() const
{
    if (std::filesystem::is_directory(traceCpPath_)) {
        for (const auto& entry : std::filesystem::directory_iterator(traceCpPath_)) {
            if (!entry.is_directory()) {
                std::filesystem::remove(entry.path());
            }
        }
    }
}

void ByTrace::CpTraceFile() const
{
    if (!std::filesystem::exists(traceCpPath_)) {
        SPUtils::CreateDir(traceCpPath_);
    }
    if (!std::filesystem::is_directory(traceCpPath_)) {
        LOGE("Destination path is not a directory.");
        return;
    }
    std::string result;
    std::string cpResult;
    constexpr const char* cpCommand = "cp -r ";
    constexpr const char* chmodCommand = "chmod 777 ";
    const std::string cpHiviewTracePath = hiviewTracePath_ + hiviewTrace;
    const std::string cpTrace = cpCommand + cpHiviewTracePath + " " + traceCpPath_;
    if (!SPUtils::LoadCmd(cpTrace, result)) {
        LOGE("Copy failed.");
        return;
    }
    std::string tracePathChmod = chmodCommand + traceCpPath_;
    if (!SPUtils::LoadCmd(tracePathChmod, result)) {
        LOGE("Chmod failed.");
        return;
    }
    LOGD("ByTrace::CpTraceFile result = (%s)", result.c_str());
}

void ByTrace::CheckFpsJitters(long long& jitters, int cfps)
{
    times++;
    const int two = 2;
    if (times > two) {
        nowTime = SPUtils::GetCurTime();
        if (lastEnableTime > 0) {
            long long diff =
                (nowTime >= lastEnableTime) ? (nowTime - lastEnableTime) : (LLONG_MAX - lastEnableTime + nowTime + 1);
            LOGD("ByTrace::Time difference: %llu ms", diff);
            if (diff > TIME_DIFF_THRESHOLD) {
                LOGW("ByTrace::Time difference exceeded threshold, resetting start capture time.");
                lastEnableTime = 0;
            }
        }
        SendSurfaceCaton(jitters, cfps);
    }
}

void ByTrace::SendSurfaceCaton(long long& jitters, int cfps)
{
    if (cfps < lowFps || jitters > jitterTimesTaken) {
        LOGD("ByTrace::SendSurfaceCaton jitters(%lld), cfps(%d)", jitters, cfps);
        if (lastEnableTime == 0) {
            lastEnableTime = nowTime;
            ipcCallback_("surfaceCaton");
        }
    }
}
}
}
