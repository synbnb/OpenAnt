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

#include "effective.h"
#include "FPS.h"
#include "sp_utils.h"
#include "sp_log.h"
#include "common.h"

namespace {
constexpr long long RM_1000000 = 1000000;
constexpr long long RM_5000 = 5000;
constexpr long long RM_0 = 0;
}
namespace OHOS {
namespace SmartPerf {
std::map<std::string, std::string> Effective::ItemData()
{
    std::map<std::string, std::string> templateMap;

    FpsCurrentFpsTime fcf = FPS::GetInstance().GetFpsCurrentFpsTime();
    long long nowTime = SPUtils::GetCurTime();
    long long curframeTime = fcf.currentFpsTime / RM_1000000; // Convert to milliseconds

    if (startCaptuerTime_ > 0) {
        long long diff =
            startCaptuerTime_ > nowTime ? (LLONG_MAX - startCaptuerTime_ + nowTime) : (nowTime - startCaptuerTime_);

        if (diff > RM_5000 && (!CheckCounterId())) {
            startCaptuerTime_ = RM_0;
        }
    }

    if (fps_ > fcf.fps || frameTime_ < curframeTime) {
        if (startCaptuerTime_ == 0) {
            startCaptuerTime_ = nowTime;
            ThreadGetHiperf(startCaptuerTime_);
        }
    }
    templateMap["fpsWarn"] = std::to_string(fcf.fps);
    templateMap["FrameTimeWarn"] = std::to_string(fcf.currentFpsTime);
    templateMap["TraceTime"] = std::to_string(startCaptuerTime_);
    LOGI("Effective:ItemData map size(%u)", templateMap.size());
    return templateMap;
}

bool Effective::CheckCounterId()
{
    std::string result;
    std::string hiprofilerCmd = CMD_COMMAND_MAP.at(CmdCommand::HIPROFILER_CMD);
    LOGD("Loading hiprofiler command");
    SPUtils::LoadCmd(hiprofilerCmd, result);
    if (result.empty()) {
        LOGW("Failed to load hiprofiler command or received empty result.");
        return false;
    }

    if (result.find("-k") != std::string::npos) {
        LOGD("Command contains '-k'.");
        return true;
    }

    LOGD("Command does not contain '-k'.");
    return false;
}
std::thread Effective::ThreadGetHiperf(long long timeStamp)
{
    auto thGetTrace = [this, timeStamp]() { this->GetHiperf(std::to_string(timeStamp)); };
    std::thread spThread(thGetTrace);
    spThread.detach();
    return spThread;
}

void Effective::GetHiperf(const std::string &traceName)
{
    std::string result;
    std::string tmp = SetHiperf(traceName);
    std::cout << tmp << std::endl;
    SPUtils::LoadCmd(tmp, result);
    LOGD("hiprofiler exec (%s), hiprofiler exec trace name(%s), hiprofiler exec end (%s)",
        tmp.c_str(), traceName.c_str(), result.c_str());
}

std::string Effective::SetHiperf(const std::string &traceName)
{
    std::string hiPrefix = "hiprofiler_";
    std::string dataPrefix = "perf_";
    requestId_++;
    std::string trtmp = strOne_ + hiPrefix + traceName + strTwo_ + "\n" + strThree_ + std::to_string(requestId_) +
        "\n" + strFour_ + "\n" + strFive_ + hiPrefix + traceName + strSix_ + "\n" + strNine_ + strEleven_ + "\n" +
        strSeven_ + dataPrefix + traceName + strEight_ + strTen_ + "\n" + conFig_;
    return trtmp;
}
}
}