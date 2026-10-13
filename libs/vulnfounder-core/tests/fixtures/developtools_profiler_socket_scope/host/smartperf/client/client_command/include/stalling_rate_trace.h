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
#ifndef STALLINGRATETRACE_H
#define STALLINGRATETRACE_H
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

namespace OHOS {
namespace SmartPerf {
class StallingRateTrace {
public:
    enum SWIM_TYPE {
        SWIM_APPLIST = 1,
        SWIM_APPSWIPER = 2,
        SWIM_APPTABS = 3,
    };
public:
    double StallingRateResult(const std::string& file);
    double CalculateTime();
    double GetFrameRate(const std::string &line) const;
    int GetFenceId(const std::string &line) const;
    std::string GetOnScreenTimeStart(const std::string &line) const;
    double GetTimes(const std::string &line, const std::string &sign) const;
    void AppList(const std::string &line, const std::string &signS, const std::string &signF);
    void APPTabs(const std::string &line, const std::string &signS, const std::string &signF);
    void AppSwiperScroll(const std::string &line, const std::string &signS, const std::string &signF);
    void GetRsHardWareRate(double curFrameRate, const std::string &line, SWIM_TYPE type);
    void GetFrameLossTime(double &curTime, double &prevTime, double &drawTime, double &totalFrameLossTime);
    void CalcFrameRate();
    void JudgFrameRate();
    void MultiLaneFrameRate();
    void AddMultiLaneFrameRate();
    void UpdateRoundTime(double curFrameRate, SWIM_TYPE type);
    bool IsAppLaunchPatternMatched(const std::string &line);
private:
    std::ifstream infile;
    double nowFrameRate = 0;
    double nowSwiperFrameRate = 0;
    double nowTabsFrameRate = 0;
    double oneThousand = 1000;
    double roundTime = 0;
    double roundSwiperTime = 0;
    double roundTabsTime = 0;
    int fenceId = 0;
    int fenceIdSwiper = 0;
    int fenceIdTabs = 0;
    double nowTime = 0;
    double nowSwiperTime = 0;
    double nowTabsTime = 0;
    double lastTime = 0;
    double lastSwiperTime = 0;
    double lastTabsTime = 0;
    double frameLossTime = 0;
    double frameLossRate = 0;
    double frameLossSwiperTime = 0;
    double frameLossTabsTime = 0;
    double swiperFrameLossRate = 0;
    double appFrameLossRate = 0;
    double tabsFrameLossRate = 0;
    double appListDynamicStartTime = 0;
    double appListDynamicFinishTime = 0;
    double appTabsDynamicStartTime = 0;
    double appTabsDynamicFinishTime = 0;
    double swiperDynamicStartTime = 0;
    double swiperDynamicFinishTime = 0;
    bool upperScreenFlag = false;
    bool upperScreenSwiperFlag = false;
    bool upperScreenTabsFlag = false;
    int swiperScrollFlag = 0;
    int swiperFlingFlag = 0;
    bool listFlag = false;
    bool tabsFlag = false;
    bool swiperFlag = false;
};
}
}
#endif // STALLINGRATETRACE_H