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
#include <vector>
#include <cstdio>
#include <sstream>
#include <iomanip>
#include "include/parse_click_response_trace.h"
#include "include/sp_utils.h"
#include "include/sp_log.h"
namespace OHOS {
namespace SmartPerf {
double ParseClickResponseTrace::ParseResponseTrace(const std::string& fileNamePath)
{
    int conversion = 1000;
    char realPath[PATH_MAX] = {0x00};
    if ((realpath(fileNamePath.c_str(), realPath) == nullptr)) {
        std::cout << "" << std::endl;
    }
    infile.open(realPath);
    if (infile.fail()) {
        LOGE("ParseClickResponseTrace open file(%s) fialed ", fileNamePath.c_str());
        return 0;
    }
    completeTime = GetLineTime();
    infile.close();
    return completeTime * conversion;
}
double ParseClickResponseTrace::GetLineTime()
{
    std::string line;
    std::string startTime = "0";
    std::string endTime = "0";
    std::string appPid = "0";
    std::string::size_type doComposition;
    size_t subNum = 5;
    while (getline(infile, line)) {
        appPid = GetPid(line, "pid", appPid);
        startTime = GetStartTime(line, startTime);
        doComposition = line.find("H:RSMainThread::DoComposition");
        if (doComposition != std::string::npos) {
            size_t position1 = line.find("....");
            size_t position2 = line.find(":");
            endTime = line.substr(position1 + subNum, position2 - position1 - subNum);
            if (SPUtilesTye::StringToSometype<float>(startTime) == 0) {
            } else {
                break;
            }
        }
    }
    completeTime = GetTime(startTime, endTime);
    return completeTime;
}
double ParseClickResponseTrace::GetTime(std::string startTime, std::string endTime)
{
    size_t point = endTime.find(".");
    float subNum = 2;
    endTime = endTime.substr(point - subNum);
    startTime = startTime.substr(point - subNum);
    if (SPUtilesTye::StringToSometype<float>(endTime) == 0 || SPUtilesTye::StringToSometype<float>(startTime) == 0) {
    } else {
        double displayTime = 0.032;
        completeTime = SPUtilesTye::StringToSometype<float>(endTime) -
                        SPUtilesTye::StringToSometype<float>(startTime) + displayTime;
    }
    return completeTime;
}
std::string ParseClickResponseTrace::GetPid(const std::string& line, const std::string &pn, const std::string &pb)
{
    std::string appPid;
    if (appPidnum == 0) {
        size_t packageNameNumSize = 5;
        std::string::size_type positionPackgeName;
        if (pn.length() < packageNameNumSize) {
            std::string::size_type positionAppspawn;
            positionPackgeName = line.find("task_newtask: pid=");
            positionAppspawn = line.find("comm=appspawn");
            if (positionPackgeName != std::string::npos && positionAppspawn != std::string::npos) {
                size_t subNum = 4;
                size_t position1 = line.find("pid=");
                size_t position2 = line.find(" comm=appspawn");
                appPid = line.substr(position1 + subNum, position2 - position1 - subNum);
                appPidnum++;
            } else {
                appPid = pb;
            }
        } else {
            positionPackgeName = line.find(pn);
            if (positionPackgeName != std::string::npos) {
                size_t p1 = line.find(pn);
                size_t p2 = line.find(" prio");
                appPid = line.substr(p1 + pn.length(), p2 - p1 - pn.length());
                appPidnum++;
            } else {
                appPid = pb;
            }
        }
    }
    return appPid;
}
std::string ParseClickResponseTrace::GetStartTime(const std::string& line, const std::string &startTimeBefore)
{
    std::string startTime;
    std::string::size_type te = line.find("H:touchEventDispatch");
    std::string::size_type td = line.find("H:TouchEventDispatch");
    std::string::size_type pd = line.find("H:PointerEventDispatch");
    std::string::size_type kd = line.find("H:KeyEventDispatch");
    std::string::size_type nop = std::string::npos;
    if (te != nop || td != nop || pd != nop || kd != nop) {
        int touchNum = 3;
        if (flagTouch <= touchNum) {
            size_t position1 = line.find("....");
            size_t position2 = line.find(":");
            size_t subNum = 5;
            startTime = line.substr(position1 + subNum, position2 - position1 - subNum);
            flagTime = "0";
            flagTouch++;
        } else {
            startTime = startTimeBefore;
        }
    } else {
        startTime = startTimeBefore;
    }
    return startTime;
}
}
}