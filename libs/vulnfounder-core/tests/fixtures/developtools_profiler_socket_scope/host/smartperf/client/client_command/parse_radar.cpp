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
#include <fstream>
#include <string>
#include <cstring>
#include <vector>
#include <cstdio>
#include <sstream>
#include <iomanip>
#include <regex>
#include <cmath>
#include "include/parse_radar.h"
#include "include/sp_utils.h"
namespace OHOS {
namespace SmartPerf {
std::string ParseRadar::ParseRadarAppStrart(const std::string &string) const
{
    std::ostringstream stream;
    std::ostringstream streamComplete;
    std::string animationCompleteTime = ExtractString(string, "\"ANIMATION_LATENCY\":");
    double completeTime = ParseRadarDelayTime(string, targetComplete, delayTimeComplete);
    streamComplete << completeTime;
    double responseTime = ParseRadarDelayTime(string, targetResponse, delayTimeResponse);
    stream << responseTime;
    std::string firstFrameDrawnTime = ExtractString(string, "\"FIRST_FRAEM_DRAWN_LATENCY\":");
    std::string result = "ResponseTime:" + stream.str() +
        "ms\n"
        "FirstFrameDrawnTime:" +
        firstFrameDrawnTime +
        "ms\n"
        "AnimationCompleteTime:" +
        animationCompleteTime +
        "ms\n"
        "CompleteTime:" +
        streamComplete.str() + "ms\n";
    return result;
}
double ParseRadar::ParseRadarResponse(const std::string &string) const
{
    double time = -1;
    time = ParseRadarDelayTime(string, targetResponse, delayTimeResponse);
    return time;
}

double ParseRadar::ParseRadarDelayTime(const std::string &string, const std::string &target, const int &delayTime) const
{
    std::stringstream ss(string);
    std::string segment;
    int maxDelayTime = -1;
    std::vector<std::string> delayTimeVec;
    while (getline(ss, segment, '}')) {
        if (segment.empty()) {
            continue;
        }
        std::string segments = segment.substr(1);
        std::stringstream ss2(segments);
        std::string pair;
        while (getline(ss2, pair, ',')) {
            std::string key = pair.substr(0, pair.find(':'));
            std::string value = pair.substr(pair.find(':') + 1);
            if (key == target) {
                delayTimeVec.push_back(value);
                maxDelayTime = GetMaxDelayTime(delayTime, delayTimeVec);
            }
        }
    }
    return static_cast<double>(maxDelayTime);
}
int ParseRadar::GetMaxDelayTime(const int &delayTime, std::vector<std::string> &delayTimeVec) const
{
    int maxNum = -1;
    for (size_t i = 0; i < delayTimeVec.size(); i++) {
        int num = SPUtilesTye::StringToSometype<int>(delayTimeVec[i]);
        if (num < delayTime && num > maxNum) {
            maxNum = num;
        }
    }
    return maxNum;
}
double ParseRadar::ParseRadarComplete(const std::string &string) const
{
    double time = -1;
    time = ParseRadarDelayTime(string, targetComplete, delayTimeComplete);
    return time;
}
std::string ParseRadar::ParseRadarMaxFrame(const std::string &string) const
{
    std::string maxRenderSeqMissedFrames = ExtractString(string, "\"MAX_RENDER_SEQ_MISSED_FRAMES\":");
    std::string result = "MAX_RENDER_SEQ_MISSED_FRAMES:" + maxRenderSeqMissedFrames;
    return result;
}
std::string ParseRadar::ParseRadarFrame(const std::string &string) const
{
    std::string budleName = ExtractString(string, "\"BUNDLE_NAME_EX\":");
    std::cout << "BUNDLE_NAME:" << budleName << std::endl;
    std::string sceneId = ExtractString(string, "\"SCENE_ID\":");
    std::cout << "SCENE_ID:" << sceneId << std::endl;
    std::string totalAppFrames = ExtractString(string, "\"TOTAL_APP_FRAMES\":");
    std::cout << "TOTAL_APP_FRAMES:" << totalAppFrames << std::endl;
    std::string totalAppMissedFrames = ExtractString(string, "\"TOTAL_APP_MISSED_FRAMES\":");
    std::cout << "TOTAL_APP_MISSED_FRAMES:" << totalAppMissedFrames << std::endl;
    std::string maxAppFramsestime = ExtractString(string, "\"MAX_APP_FRAMETIME\":");
    std::cout << "MAX_APP_FRAMETIME:" << maxAppFramsestime << "ms" << std::endl;
    std::string maxAppSeqMissedFrames = ExtractString(string, "\"MAX_APP_SEQ_MISSED_FRAMES\":");
    std::cout << "MAX_APP_SEQ_MISSED_FRAMES:" << maxAppSeqMissedFrames << std::endl;
    std::string totalRenderFrames = ExtractString(string, "\"TOTAL_RENDER_FRAMES\":");
    std::cout << "TOTAL_RENDER_FRAMES:" << totalRenderFrames << std::endl;
    std::string totalRenderMissedFrames = ExtractString(string, "\"TOTAL_RENDER_MISSED_FRAMES\":");
    std::cout << "TOTAL_RENDER_MISSED_FRAMES:" << totalRenderMissedFrames << std::endl;
    std::string maxRenderFrametime = ExtractString(string, "\"MAX_RENDER_FRAMETIME\":");
    std::cout << "MAX_RENDER_FRAMETIME:" << maxRenderFrametime << "ms" << std::endl;
    std::string averageRenderFrametime = ExtractString(string, "\"AVERAGE_RENDER_FRAMETIME\":");
    std::cout << "AVERAGE_RENDER_FRAMETIME:" << averageRenderFrametime << "ms" << std::endl;
    std::string maxRenderSeqMissedFrames = ExtractString(string, "\"MAX_RENDER_SEQ_MISSED_FRAMES\":");
    std::cout << "MAX_RENDER_SEQ_MISSED_FRAMES:" << maxRenderSeqMissedFrames << std::endl;
    std::string result = "";
    return result;
}
std::string ParseRadar::ExtractString(const std::string &str, const std::string &target) const
{
    size_t pos = str.find(target);
    if (pos != std::string::npos) {
        pos += target.length();
        size_t commaPos = str.find(",", pos);
        if (commaPos != std::string::npos) {
            std::string result = str.substr(pos, commaPos - pos);
            return result;
        }
    }

    return "-1";
}
}
}