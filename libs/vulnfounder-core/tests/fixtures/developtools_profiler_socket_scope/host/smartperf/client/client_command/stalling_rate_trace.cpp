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
#include <fstream>
#include <string>
#include <iostream>
#include <regex>
#include <cmath>
#include <unordered_set>
#include "include/stalling_rate_trace.h"
#include "include/sp_log.h"
#include "include/sp_utils.h"

namespace OHOS {
namespace SmartPerf {
double StallingRateTrace::StallingRateResult(const std::string& file)
{
    double stalligRate = 0;
    char realPath[PATH_MAX] = {0x00};
    if ((realpath(file.c_str(), realPath) == nullptr)) {
        std::cout << "" << std::endl;
    }
    infile.open(realPath);
    if (infile.fail()) {
        LOGE("StallingRateTrace open file(%s) fialed ", file.c_str());
        return stalligRate;
    }
    stalligRate = SmartPerf::StallingRateTrace::CalculateTime();
    infile.close();
    return stalligRate;
}

double StallingRateTrace::CalculateTime()
{
    frameLossRate = 0;
    frameLossTime = 0;
    swiperFrameLossRate = 0;
    appFrameLossRate = 0;
    tabsFrameLossRate = 0;
    frameLossSwiperTime = 0;
    frameLossTabsTime = 0;
    std::string signS = "S|";
    std::string signF = "F|";
    std::string line;
    while (getline(infile, line)) {
        AppList(line, signS, signF);
        AppSwiperScroll(line, signS, signF);
        APPTabs(line, signS, signF);
    }
    CalcFrameRate();
    JudgFrameRate();
    MultiLaneFrameRate();
    return frameLossRate;
}

void StallingRateTrace::CalcFrameRate()
{
    if (appListDynamicStartTime != 0 && appListDynamicFinishTime != 0) {
        appFrameLossRate = (frameLossTime / (appListDynamicFinishTime - appListDynamicStartTime) * oneThousand);
    } else {
        appFrameLossRate = -1;
    }

    if (swiperDynamicFinishTime != 0 && swiperDynamicStartTime != 0) {
        swiperFrameLossRate = (frameLossSwiperTime / (swiperDynamicFinishTime - swiperDynamicStartTime) * oneThousand);
    } else {
        swiperFrameLossRate = -1;
    }

    if (appTabsDynamicStartTime != 0 && appTabsDynamicFinishTime != 0) {
        tabsFrameLossRate = (frameLossTabsTime / (appTabsDynamicFinishTime - appTabsDynamicStartTime) * oneThousand);
    } else {
        tabsFrameLossRate = -1;
    }
    LOGD("result.appFrameLossRate: (%s), result.swiperFrameLossRate: (%s), result.tabsFrameLossRate: (%s)",
        std::to_string(appFrameLossRate).c_str(),
        std::to_string(swiperFrameLossRate).c_str(),
        std::to_string(tabsFrameLossRate).c_str());
}

void StallingRateTrace::JudgFrameRate()
{
    auto hasDynamic = [](bool finishTime, bool startTime) {
        return finishTime != 0 || startTime != 0;
    };

    bool appListDynamicExists = hasDynamic(appListDynamicFinishTime, appListDynamicStartTime);
    bool swiperDynamicExists = hasDynamic(swiperDynamicFinishTime, swiperDynamicStartTime);
    bool tabsDynamicExists = hasDynamic(appTabsDynamicFinishTime, appTabsDynamicStartTime);

    if (!appListDynamicExists) {
        LOGD("no app list Dynamic"); //没有APP list泳道
        frameLossRate = swiperDynamicExists ? swiperFrameLossRate :
                        tabsDynamicExists ? tabsFrameLossRate : -1;
    } else if (!swiperDynamicExists) {
        LOGD("no swiper Dynamic"); //没有swiper 泳道
        frameLossRate = appListDynamicExists ? appFrameLossRate :
                        tabsDynamicExists ? tabsFrameLossRate : -1;
    } else if (!tabsDynamicExists) {
        LOGD("no tabs Dynamic"); //没有tabs 泳道
        frameLossRate = appListDynamicExists ? appFrameLossRate :
                        swiperDynamicExists ? swiperFrameLossRate : -1;
    } else {
        frameLossRate = -1;
    }
}

void StallingRateTrace::MultiLaneFrameRate()
{
    if (appFrameLossRate == 0) {
        if (swiperFrameLossRate > 0) {
            LOGD("no app list hitchTime"); //没有app list卡顿次数
            frameLossRate = swiperFrameLossRate;
        } else if (tabsFrameLossRate > 0) {
            frameLossRate = tabsFrameLossRate;
        } else {
            frameLossRate = 0;
        }
    } else if (swiperFrameLossRate == 0) {
        LOGD("no swiper list hitchTime"); //没有swiper list卡顿次数
        if (appFrameLossRate > 0) {
            frameLossRate = appFrameLossRate;
        } else if (tabsFrameLossRate > 0) {
            frameLossRate = tabsFrameLossRate;
        } else {
            frameLossRate = 0;
        }
    } else if (tabsFrameLossRate == 0) {
        LOGD("no tabs list hitchTime"); //没有tabs list卡顿次数
        if (appFrameLossRate > 0) {
            frameLossRate = appFrameLossRate;
        } else if (swiperFrameLossRate > 0) {
            frameLossRate = swiperFrameLossRate;
        }
    }
    AddMultiLaneFrameRate();
}

void StallingRateTrace::AddMultiLaneFrameRate()
{
    if (appFrameLossRate > 0 && swiperFrameLossRate > 0) {
        //app and swiper hitchTime 1
        if (appListDynamicStartTime < swiperDynamicStartTime) {
            frameLossRate = appFrameLossRate;
        } else {
            frameLossRate = swiperFrameLossRate;
        }
    } else if (appFrameLossRate > 0 && tabsFrameLossRate > 0) {
        //app and tabs hitchTime 2
        if (appListDynamicStartTime < appTabsDynamicStartTime) {
            frameLossRate = appFrameLossRate;
        } else {
            frameLossRate = appTabsDynamicStartTime;
        }
    } else if (tabsFrameLossRate > 0 && swiperFrameLossRate > 0) {
        //tabs and swiper hitchTime 3
        if (appTabsDynamicStartTime < swiperDynamicStartTime) {
            frameLossRate = tabsFrameLossRate;
        } else {
            frameLossRate = swiperFrameLossRate;
        }
    }
}


void StallingRateTrace::AppList(const std::string &line, const std::string &signS, const std::string &signF)
{
    if (IsAppLaunchPatternMatched(line)) {
        if (listFlag) {
            appListDynamicFinishTime = GetTimes(line, signF);
            LOGD("AppList line start: (%s), appListDynamicFinishTime: (%s)",
                line.c_str(), std::to_string(appListDynamicFinishTime).c_str());
            listFlag = false;
        } else {
            appListDynamicStartTime = GetTimes(line, signS);
            LOGD("AppList line finish: (%s), appListDynamicStartTime: (%s)",
                line.c_str(), std::to_string(appListDynamicStartTime).c_str());
            listFlag = true;
            frameLossTime = 0;
        }
    }
    if (listFlag) {
        GetRsHardWareRate(nowFrameRate, line, SWIM_APPLIST);
        if (upperScreenFlag) {
            if (line.find("|H:Present Fence ") != std::string::npos) {
                fenceId = GetFenceId(line);
                LOGD("fenceID:(%d)", fenceId);
            }
            std::string waitFenceId = "|H:Waiting for Present Fence " + std::to_string(fenceId);
            if (line.find(waitFenceId) != std::string::npos) {
                nowTime = SPUtilesTye::StringToSometype<double>(StallingRateTrace::GetOnScreenTimeStart(line));
                GetFrameLossTime(nowTime, lastTime, roundTime, frameLossTime);
                LOGD("frameLossTime: (%s)", std::to_string(frameLossTime).c_str());
                lastTime = nowTime;
                upperScreenFlag = false;
            }
        }
    }
}

void StallingRateTrace::GetFrameLossTime(double &curTime, double &prevTime,
    double &drawTime, double &totalFrameLossTime)
{
    if ((curTime - prevTime) > drawTime && prevTime != 0) {
        double diffTime = (curTime - prevTime) - drawTime;
        totalFrameLossTime += diffTime;
        LOGD("diffTime: (%s), totalFrameLossTime: (%s)",
            std::to_string(diffTime).c_str(), std::to_string(totalFrameLossTime).c_str());
    }
}

void StallingRateTrace::GetRsHardWareRate(double curFrameRate, const std::string &line, SWIM_TYPE type)
{
    if (line.find("H:RSHardwareThread::CommitAndReleaseLayers") != std::string::npos) {
        switch (type) {
            case SWIM_APPLIST:
                upperScreenFlag = true;
                break;
            case SWIM_APPSWIPER:
                upperScreenSwiperFlag = true;
                break;
            case SWIM_APPTABS:
                upperScreenTabsFlag = true;
                break;
            default:
                break;
        }
        curFrameRate = GetFrameRate(line);
        if (curFrameRate != 0) {
            UpdateRoundTime(curFrameRate, type);
        }
    } else if (line.find("H:RSHardwareThread::PerformSetActiveMode setting active mode") != std::string::npos) {
        switch (type) {
            case SWIM_APPLIST:
                upperScreenFlag = true;
                break;
            case SWIM_APPSWIPER:
                upperScreenSwiperFlag = true;
                break;
            case SWIM_APPTABS:
                upperScreenTabsFlag = true;
                break;
            default:
                break;
        }
        curFrameRate = GetFrameRate(line);
        if (curFrameRate != 0) {
            UpdateRoundTime(curFrameRate, type);
        }
    }
}

void StallingRateTrace::UpdateRoundTime(double curFrameRate, SWIM_TYPE type)
{
    const double kadunNum = 1.5;
    const double num = 1;
    if (curFrameRate != 0) {
        switch (type) {
            case SWIM_APPLIST:
                roundTime = (num / curFrameRate) * kadunNum;
                break;
            case SWIM_APPSWIPER:
                roundSwiperTime = (num / curFrameRate) * kadunNum;
                break;
            case SWIM_APPTABS:
                roundTabsTime = (num / curFrameRate) * kadunNum;
                break;
            default:
                break;
        }
    }
}

void StallingRateTrace::AppSwiperScroll(const std::string &line, const std::string &signS, const std::string &signF)
{
    if (IsAppLaunchPatternMatched(line)) {
        if (swiperScrollFlag == 0) {
            swiperDynamicStartTime = GetTimes(line, signS);
            LOGD("AppSwiperScroll line start: (%s), swiperDynamicStartTime: (%s)",
                line.c_str(), std::to_string(swiperDynamicStartTime).c_str());
            frameLossSwiperTime = 0;
            swiperScrollFlag = 1;
            swiperFlag = true;
        }
    }
    if (IsAppLaunchPatternMatched(line)) {
        if (swiperFlingFlag == 1) {
            swiperDynamicFinishTime = GetTimes(line, signF);
            LOGD("AppSwiper FinishTime line: (%s), swiperDynamicFinishTime: (%s)",
                line.c_str(), std::to_string(swiperDynamicFinishTime).c_str());
            swiperFlag = false;
        }
        if (swiperDynamicFinishTime == 0) {
            swiperFlingFlag = 0;
        }
        swiperFlingFlag++;
    }
    if (swiperFlag) {
        GetRsHardWareRate(nowSwiperFrameRate, line, SWIM_APPSWIPER);
        if (upperScreenSwiperFlag) {
            if (line.find("|H:Present Fence ") != std::string::npos) {
                fenceIdSwiper = GetFenceId(line);
            }
            std::string waitFenceId = "|H:Waiting for Present Fence " + std::to_string(fenceIdSwiper);
            if (line.find(waitFenceId) != std::string::npos) {
                nowSwiperTime = SPUtilesTye::StringToSometype<double>(StallingRateTrace::GetOnScreenTimeStart(line));
                GetFrameLossTime(nowSwiperTime, lastSwiperTime, roundSwiperTime, frameLossSwiperTime);
                LOGD("nowSwiperTime: (%s), frameLossSwiperTime: (%s)",
                    std::to_string(nowSwiperTime).c_str(), std::to_string(frameLossSwiperTime).c_str());
                lastSwiperTime = nowSwiperTime;
                upperScreenSwiperFlag = false;
            }
        }
    }
}

void StallingRateTrace::APPTabs(const std::string &line, const std::string &signS, const std::string &signF)
{
    if (IsAppLaunchPatternMatched(line)) {
        if (tabsFlag) {
            appTabsDynamicFinishTime = GetTimes(line, signF);
            LOGD("APPTabs line start: (%s), appTabsDynamicFinishTime: (%s)",
                line.c_str(), std::to_string(appTabsDynamicFinishTime).c_str());
            tabsFlag = false;
        } else {
            appTabsDynamicStartTime = GetTimes(line, signS);
            LOGD("APPTabs line finish: (%s), appTabsDynamicStartTime: (%s)",
                line.c_str(), std::to_string(appTabsDynamicStartTime).c_str());
            tabsFlag = true;
            frameLossTabsTime = 0;
        }
    }
    if (tabsFlag) {
        GetRsHardWareRate(nowTabsFrameRate, line, SWIM_APPTABS);
        if (upperScreenTabsFlag) {
            if (line.find("|H:Present Fence ") != std::string::npos) {
                fenceIdTabs = GetFenceId(line);
            }
            std::string waitFenceId = "|H:Waiting for Present Fence " + std::to_string(fenceIdTabs);
            if (line.find(waitFenceId) != std::string::npos) {
                nowTabsTime = SPUtilesTye::StringToSometype<double>(GetOnScreenTimeStart(line));
                GetFrameLossTime(nowTabsTime, lastTabsTime, roundTabsTime, frameLossTabsTime);
                lastTabsTime = nowTabsTime;
                upperScreenTabsFlag = false;
            }
        }
    }
}

double StallingRateTrace::GetFrameRate(const std::string &line) const
{
    double rate = 0;
    std::string delimiter = "rate: ";
    if (line.find("now:") != std::string::npos && line.find("rate:") != std::string::npos) {
        std::string delimiter1 = ", now:";
        size_t pos1 = line.find(delimiter);
        std::string result1 = line.substr(pos1 + delimiter.length());
        size_t pos2 = line.find(delimiter1);
        std::string result2 = result1.substr(0, pos2);
        rate = SPUtilesTye::StringToSometype<double>(result2.c_str());
    }
    if (line.find("rate:") != std::string::npos) {
        size_t pos = line.find(delimiter);
        std::string result = line.substr(pos + delimiter.length());
        rate = SPUtilesTye::StringToSometype<double>(result.c_str());
    }
    return rate;
}

int StallingRateTrace::GetFenceId(const std::string &line) const
{
    std::string delimiter = "H:Present Fence ";
    size_t pos = line.find(delimiter);
    std::string result = line.substr(pos + delimiter.length());
    return SPUtilesTye::StringToSometype<int>(result.c_str());
}

std::string StallingRateTrace::GetOnScreenTimeStart(const std::string &line) const
{
    size_t subNum = 7;
    size_t positionFirst = line.find("....");
    size_t positionSecond = line.find(":");
    return line.substr(positionFirst + subNum, positionSecond - positionFirst - subNum);
}

double StallingRateTrace::GetTimes(const std::string &line, const std::string &sign) const
{
    size_t positionFirst = line.find("....");
    size_t positionSecond = line.find(":");
    if (positionFirst != std::string::npos && positionSecond != std::string::npos) {
        if (line.find(sign) != std::string::npos) {
            size_t subNum = 7;
            return SPUtilesTye::StringToSometype<double>(line.substr(
                positionFirst + subNum, positionSecond - positionFirst - subNum));
        }
    }
    return 0.0;
}
bool StallingRateTrace::IsAppLaunchPatternMatched(const std::string &line)
{
    static const std::unordered_set<std::string> appLaunchPatterns = {
        "H:LAUNCHER_APP_LAUNCH_FROM_ICON,",
        "H:APP_LIST_FLING,",
        "H:WEB_LIST_FLING",
        "H:ABILITY_OR_PAGE_SWITCH,",
        "H:APP_TRANSITION_TO_OTHER_APP,",
        "H:LAUNCHER_APP_LAUNCH_FROM_DOCK,",
        "H:LAUNCHER_APP_LAUNCH_FROM_APPCENTER,",
        "H:APP_SWIPER_NO_ANIMATION_SWITCH",
        "H:APP_SWITCH_FRAME_ANIMATION",
        "H:APP_SWIPER_SCROLL,",
        "H:APP_SWIPER_FLING,",
        "H:APP_TABS_NO_ANIMATION_SWITCH",
        "H:APP_TABS_FRAME_ANIMATION",
        "H:APP_TABS_SCROLL,"
    };
    for (const auto &keyWords : appLaunchPatterns) {
        size_t pos = line.find(keyWords);
        if (pos != std::string::npos) {
            if (pos > 0 && isspace(line[pos - 1])) {
                continue;
            }
            if (pos + keyWords.length() < line.length() && !isspace(line[pos + keyWords.length()]) &&
                line[pos + keyWords.length()] != ',') {
                continue;
            }
            if (pos + keyWords.length() < line.length() && (line[pos + keyWords.length()] == ',')) {
                return false;
            }
            LOGD("StallingRateTrace::IsAppLaunchPatternMatched: (%s)", keyWords.c_str());
            return true;
        }
    }
    return false;
}
}
}
