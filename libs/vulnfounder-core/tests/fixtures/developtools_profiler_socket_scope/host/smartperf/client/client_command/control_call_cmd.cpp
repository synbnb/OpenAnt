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
#include "unistd.h"
#include <thread>
#include <cstdio>
#include <cstring>
#include <map>
#include <sstream>
#include <iomanip>
#include <future>
#include "include/control_call_cmd.h"
#include "include/startup_delay.h"
#include "include/sp_utils.h"
#include "include/parse_click_complete_trace.h"
#include "include/parse_click_response_trace.h"
#include "include/parse_radar.h"
#include "include/parse_slide_fps_trace.h"
#include "include/sp_log.h"
#include "include/stalling_rate_trace.h"
#include "common.h"

namespace OHOS {
namespace SmartPerf {
std::string ControlCallCmd::GetResult(const std::vector<std::string>& v)
{
    IsohTest(v);
    if (v[typeName] == "responseTime") {
        time = SmartPerf::ControlCallCmd::ResponseTime();
    } else if (v[typeName] == "completeTime") {
        time = SmartPerf::ControlCallCmd::CompleteTime();
    } else if (v[typeName] == "fpsohtest") {
        std::string ohTestFps = CMD_COMMAND_MAP.at(CmdCommand::OHTESTFPS);
        SPUtils::LoadCmd(ohTestFps, result);
    } else if (v[typeName] == "frameLoss") {
        result = SmartPerf::ControlCallCmd::GetFrame();
    } else if (v[typeName] == "appStartTime") {
        result = ControlCallCmd::GetAppStartTime();
    } else if (v[typeName] == "slideList") {
        result = ControlCallCmd::SlideList();
    } else if (v[typeName] == "timeDelay") {
        result = ControlCallCmd::TimeDelay();
    }
    if (time == noNameType) {
        std::cout << "Startup error, unknown application or application not responding" << std::endl;
    } else {
        if (time != 0) {
            stream << time;
            result = "time:" + stream.str() + "ms";
        }
        std::cout << result << std::endl;
    }
    return result;
}
std::string ControlCallCmd::TimeDelay()
{
    OHOS::SmartPerf::ParseClickResponseTrace pcrt;
    OHOS::SmartPerf::StartUpDelay sd;
    std::string cmdResult;
    OHOS::SmartPerf::ParseRadar radar;
    OHOS::SmartPerf::StallingRateTrace srt;
    std::string rmTrace = CMD_COMMAND_MAP.at(CmdCommand::RM_FILE) + std::string("sp_trace_") + "delay" + ".ftrace";
    SPUtils::LoadCmd(rmTrace, cmdResult);
    std::string traceName = std::string("/data/local/tmp/") + std::string("sp_trace_") + "delay" + ".ftrace";
    std::thread thGetTrace = std::thread([&sd, traceName]() { sd.GetTrace(traceName); });
    std::thread thGetHisysId = std::thread([&sd]() { sd.GetHisysIdAndKill(); });
    std::promise<std::string> promResponse;
    std::promise<std::string> promComplete;
    std::promise<std::string> promRadarFrame;
    std::promise<std::string> promResponseMoved = std::move(promResponse);
    std::promise<std::string> promCompleteMoved = std::move(promComplete);
    std::promise<std::string> promRadarFrameMoved = std::move(promRadarFrame);
    std::future<std::string> futureResponse = promResponseMoved.get_future();
    std::thread([promiseResponse = std::move(promResponseMoved)]() mutable {
        promiseResponse.set_value(SPUtils::GetRadarResponse());
    }).detach();
    std::future<std::string> futureComplete = promCompleteMoved.get_future();
    std::thread([promiseComplete = std::move(promCompleteMoved)]() mutable {
        promiseComplete.set_value(SPUtils::GetRadarComplete());
    }).detach();
    std::future<std::string> futureRadarFrame = promRadarFrameMoved.get_future();
    std::thread([promiseRadarFrame = std::move(promRadarFrameMoved)]() mutable {
        promiseRadarFrame.set_value(SPUtils::GetRadarFrame());
    }).detach();
    std::string responseStr = futureResponse.get();
    std::string completeStr = futureComplete.get();
    std::string radarFrameStr = futureRadarFrame.get();
    thGetTrace.join();
    thGetHisysId.join();
    double strResponseTime = radar.ParseRadarResponse(responseStr);
    stream << strResponseTime;
    double strCompleteTime = radar.ParseRadarComplete(completeStr);
    std::ostringstream streamComplete;
    streamComplete << strCompleteTime;
    std::string maxFrame = radar.ParseRadarMaxFrame(radarFrameStr);
    std::string resultTime = "ResponseTime:" + stream.str() + "ms\n" + "CompleteTime:" + streamComplete.str() + "ms\n";
    double rateResult = srt.StallingRateResult(traceName);
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(two) << rateResult;
    HitchTimeRateData(ss);
    return resultTime + "HitchTimeRate:" + ssResult_ + "ms/s \n" + maxFrame;
}
std::string ControlCallCmd::SlideList()
{
    OHOS::SmartPerf::ParseClickResponseTrace pcrt;
    OHOS::SmartPerf::StartUpDelay sd;
    OHOS::SmartPerf::ParseSlideFpsTrace slideFpsTrace;
    std::string cmdResult;
    OHOS::SmartPerf::ParseRadar radar;
    OHOS::SmartPerf::StallingRateTrace srt;
    std::string resultStream = "";
    std::string rmTrace = CMD_COMMAND_MAP.at(CmdCommand::RM_FILE) + std::string("sp_trace_") + "fps" + ".ftrace";
    SPUtils::LoadCmd(rmTrace, cmdResult);
    std::string traceName = std::string("/data/local/tmp/") + std::string("sp_trace_") + "fps" + ".ftrace";
    if (isOhTest) {
        std::thread thGetTrace = std::thread([&sd, traceName]() { sd.GetTrace(traceName); });
        thGetTrace.join();
        time = pcrt.ParseResponseTrace(traceName);
    } else {
        std::thread thGetTrace = std::thread([&sd, traceName]() { sd.GetTrace(traceName); });
        std::thread thGetHisysId = std::thread([&sd]() { sd.GetHisysIdAndKill(); });
        std::promise<std::string> promResponse;
        std::promise<std::string> promRadarFrame;
        std::promise<std::string> promResponseMoved = std::move(promResponse);
        std::promise<std::string> promRadarFrameMoved = std::move(promRadarFrame);
        std::future<std::string> futureResponse = promResponseMoved.get_future();
        std::thread([promiseResponse = std::move(promResponseMoved)]() mutable {
            promiseResponse.set_value(SPUtils::GetRadarResponse());
        }).detach();
        std::future<std::string> futureRadarFrame = promRadarFrameMoved.get_future();
        std::thread([promiseRadarFrame = std::move(promRadarFrameMoved)]() mutable {
            promiseRadarFrame.set_value(SPUtils::GetRadarFrame());
        }).detach();
        std::string responseStr = futureResponse.get();
        std::string radarFrameStr = futureRadarFrame.get();
        thGetTrace.join();
        thGetHisysId.join();
        double responseTime = radar.ParseRadarResponse(responseStr);
        stream << responseTime;
        std::string maxFrame = radar.ParseRadarMaxFrame(radarFrameStr);
        std::string responseSlide = "ResponseTime:" + stream.str() + "ms\n";
        double sFps = slideFpsTrace.ParseSlideFpsTraceNoh(traceName);
        std::ostringstream streamFps;
        streamFps << sFps;
        double stallingRateResult = srt.StallingRateResult(traceName);
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(two) << stallingRateResult;
        HitchTimeRateData(ss);
        std::string hitchTimeRate = "HitchTimeRate:" + ssResult_ + "ms/s \n";
        resultStream = "FPS:" + streamFps.str() + "fps\n" + responseSlide + hitchTimeRate + maxFrame;
    }
    return resultStream;
}
std::string ControlCallCmd::GetFrame()
{
    OHOS::SmartPerf::StartUpDelay sd;
    std::string cmdResult;
    OHOS::SmartPerf::ParseRadar radar;
    std::string rmTrace = CMD_COMMAND_MAP.at(CmdCommand::RM_FILE) + std::string("sp_trace_") + "frame" + ".ftrace";
    SPUtils::LoadCmd(rmTrace, cmdResult);
    std::string traceName = std::string("/data/local/tmp/") + std::string("sp_trace_") + "frame" + ".ftrace";
    std::thread thGetTrace = std::thread([&sd, traceName]() { sd.GetTrace(traceName); });
    std::thread thGetHisysId = std::thread([&sd]() { sd.GetHisysIdAndKill(); });
    std::string str = SPUtils::GetRadarFrame();
    thGetTrace.join();
    thGetHisysId.join();
    std::string reslut = radar.ParseRadarFrame(str);
    return result;
}
double ControlCallCmd::ResponseTime()
{
    OHOS::SmartPerf::ParseClickResponseTrace pcrt;
    OHOS::SmartPerf::StartUpDelay sd;
    std::string cmdResult;
    OHOS::SmartPerf::ParseRadar radar;
    std::string rmTrace = CMD_COMMAND_MAP.at(CmdCommand::RM_FILE) + "*" + ".ftrace";
    SPUtils::LoadCmd(rmTrace, cmdResult);
    std::string traceName = std::string("/data/local/tmp/") + std::string("sp_trace_") + "response" + ".ftrace";
    if (isOhTest) {
        std::thread([&sd, traceName]() { sd.GetTrace(traceName); }).join();
        time = pcrt.ParseResponseTrace(traceName);
    } else {
        std::thread thGetTrace = std::thread([&sd, traceName]() { sd.GetTrace(traceName); });
        std::thread thGetHisysId = std::thread([&sd]() { sd.GetHisysId(); });
        std::string str = SPUtils::GetRadarResponse();
        thGetTrace.join();
        thGetHisysId.join();
        time = radar.ParseRadarResponse(str);
    }
    LOGD("ResponseTime = %d", time);
    return time;
}
double ControlCallCmd::CompleteTime()
{
    OHOS::SmartPerf::StartUpDelay sd;
    OHOS::SmartPerf::ParseClickCompleteTrace pcct;
    std::string cmdResult;
    OHOS::SmartPerf::ParseRadar radar;
    std::string rmTrace = CMD_COMMAND_MAP.at(CmdCommand::RM_FILE) + "*" + ".ftrace";
    SPUtils::LoadCmd(rmTrace, cmdResult);
    std::string traceName = std::string("/data/local/tmp/") + std::string("sp_trace_") + "complete" + ".ftrace";
    if (isOhTest) {
        std::thread([&sd, traceName]() { sd.GetTrace(traceName); }).join();
        time = pcct.ParseCompleteTrace(traceName);
    } else {
        std::thread thGetTrace = std::thread([&sd, traceName]() { sd.GetTrace(traceName); });
        std::thread thGetHisysId = std::thread([&sd]() { sd.GetHisysId(); });
        std::string str = SPUtils::GetRadarComplete();
        thGetTrace.join();
        thGetHisysId.join();
        time = radar.ParseRadarComplete(str);
    }
    LOGD("CompleteTime = %d", time);
    return time;
}
std::string ControlCallCmd::GetAppStartTime()
{
    OHOS::SmartPerf::StartUpDelay sd;
    std::string cmdResult;
    OHOS::SmartPerf::ParseRadar radar;
    OHOS::SmartPerf::StallingRateTrace srt;
    std::string rmTrace = CMD_COMMAND_MAP.at(CmdCommand::RM_FILE) + std::string("sp_trace_") + "start" + ".ftrace";
    SPUtils::LoadCmd(rmTrace, cmdResult);
    std::string traceName = std::string("/data/local/tmp/") + std::string("sp_trace_") + "start" + ".ftrace";
    std::thread thGetTrace = std::thread([&sd, traceName]() { sd.GetTrace(traceName); });
    std::thread thGetHisysId = std::thread([&sd]() { sd.GetHisysIdAndKill(); });

    std::promise<std::string> promRadar;
    std::promise<std::string> promRadarFrame;
    std::promise<std::string> promRadarMoved = std::move(promRadar);
    std::promise<std::string> promRadarFrameMoved = std::move(promRadarFrame);
    std::future<std::string> futureRadar = promRadarMoved.get_future();
    std::thread([promiseRadar = std::move(promRadarMoved)]() mutable {
        promiseRadar.set_value(SPUtils::GetRadar());
    }).detach();
    std::future<std::string> futureRadarFrame = promRadarFrameMoved.get_future();
    std::thread([promiseRadarFrame = std::move(promRadarFrameMoved)]() mutable {
        promiseRadarFrame.set_value(SPUtils::GetRadarFrame());
    }).detach();
    std::string radarStr = futureRadar.get();
    std::string radarFrameStr = futureRadarFrame.get();
    thGetTrace.join();
    thGetHisysId.join();
    std::string resultStream = radar.ParseRadarAppStrart(radarStr);
    std::string resultStream2 = radar.ParseRadarMaxFrame(radarFrameStr);
    double stallingRateResult2 = srt.StallingRateResult(traceName);
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(two) << stallingRateResult2;
    HitchTimeRateData(ss);
    std::string hitchTimeRate = "HitchTimeRate:" + ssResult_ + "ms/s \n";
    resultStream = resultStream + hitchTimeRate + resultStream2;
    return resultStream;
}
void ControlCallCmd::IsohTest(const std::vector<std::string>& v)
{
    if (v[ohType] == "ohtest") {
        isOhTest = true;
    }
}

void ControlCallCmd::HitchTimeRateData(std::ostringstream &ss)
{
    ssResult_ = ss.str();
    if (ssResult_.find("-1") != std::string::npos) {
        ssResult_ = "0.00";
    }
}
}
}
