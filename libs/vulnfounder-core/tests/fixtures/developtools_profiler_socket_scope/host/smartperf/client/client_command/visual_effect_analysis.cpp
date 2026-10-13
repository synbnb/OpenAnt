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

#include "visual_effect_analysis.h"
#include "include/sp_utils.h"
#include <iostream>
#include <unistd.h>
#include "include/sp_log.h"
#include <iomanip>
#include <ctime>
#include "include/sp_csv_util.h"
#include "include/sp_task.h"
#include "include/Power.h"
#include <dirent.h>

namespace OHOS {
namespace SmartPerf {
void VisualEffectAnalysis::InitIndexInfo()
{
    std::string cyclePath = "/data/local/tmp/smartperf/1";
    SPTask::GetInstance().CreatPath(cyclePath);
    rsDataCsv_ = cyclePath + rsDataCsv_;
    feDataCsv_ = cyclePath + feDataCsv_;
}

void VisualEffectAnalysis::GetDeviceCpuNum()
{
    std::string cpuNum = SPUtils::GetCpuNum();
    std::string value = "";
    size_t pos = cpuNum.rfind("||");
    if (pos != std::string::npos) {
        int cpuNumMark = 2;
        value = cpuNum.substr(pos + cpuNumMark);
    }
    for (int i = 0; i < SPUtilesTye::StringToSometype<int>(value); i++) {
        cpuData_.push_back("cpu" + std::to_string(i) + "Frequency");
    }
}

void VisualEffectAnalysis::GetDeviceDdrNum()
{
    int ddrNum = 0;
    DIR* directory = opendir(ddrClusterPath_.c_str());
    if (directory == nullptr) {
        LOGE("open dir error");
        return;
    }
    struct dirent* entry;
    while ((entry = readdir(directory)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        ddrData_.push_back("ddr" + std::to_string(ddrNum) + "Frequency");
        ddrNum++;
    }
    closedir(directory);
}

void VisualEffectAnalysis::InitdynamicEffectRsData()
{
    dynamic_Effect_Rs_Data_["timestamp"] = "0";
    dynamic_Effect_Rs_Data_["rsCpuCycle"] = "0";
    dynamic_Effect_Rs_Data_["utCpuCycle"] = "0";
    dynamic_Effect_Rs_Data_["refreshRate"] = "0";
    dynamic_Effect_Rs_Data_["rdFps"] = "0";
    dynamic_Effect_Rs_Data_["gpuLoad"] = "0";
    dynamic_Effect_Rs_Data_["gpuFrequency"] = "0";
    for (const auto &cpuNum : cpuData_) {
        dynamic_Effect_Rs_Data_[cpuNum] = "0";
    }
    for (const auto &ddrNum : ddrData_) {
        dynamic_Effect_Rs_Data_[ddrNum] = "0";
    }
}

void VisualEffectAnalysis::InitdynamicEffectFeData()
{
    dynamic_Effect_Fe_Data_["gpuCycle"] = "0";
    dynamic_Effect_Fe_Data_["timestamp"] = "0";
    dynamic_Effect_Fe_Data_["externalMemoryRead"] = "0";
    dynamic_Effect_Fe_Data_["externalMemoryWrite"] = "0";
    dynamic_Effect_Fe_Data_["externalMemoryTraffic"] = "0";
}

void VisualEffectAnalysis::CapturingTraces()
{
    std::string cmdresult = "";
    InitIndexInfo();
    GetDeviceCpuNum();
    GetDeviceDdrNum();
    InitdynamicEffectRsData();
    std::system(countersGather_.c_str());
    SPUtils::LoadCmd(endFtrace_, cmdresult);
    SPUtils::LoadCmd(geginFtrace_, cmdresult);
    beginCollTraceTime_ = SPUtils::GetCurTime();
    std::thread([this]() {
        this->GetCyclePower();
    }).detach();
    sleep(ftraceTime_ / oneMin_);
    SPUtils::LoadCmd(overtrace_, cmdresult);
    std::string permissCmd = "chmod 755 " + tracePase_;
    SPUtils::LoadCmd(permissCmd, cmdresult);
    sleep(1);
    ParsingTrace();
}

void VisualEffectAnalysis::GetCyclePower()
{
    std::unique_lock<std::mutex> lock(mtx_);
    long long powerBeginTime = SPUtils::GetCurTime();
    long long powerOvetTime = 0;
    while (powerOvetTime - powerBeginTime < ftraceTime_) {
        std::map <std::string, std::string> result = Power::GetInstance().ItemData();
        powerOvetTime = SPUtils::GetCurTime();
        powerMap_["powerTime"] = std::to_string(powerOvetTime);
        powerMap_["currentNow"] = result["currentNow"];
        powerMap_["voltageNow"] = result["voltageNow"];
        powerResult_.push_back(powerMap_);
        std::this_thread::sleep_for(std::chrono::milliseconds(oneHundred_));
    }
    return;
}

void VisualEffectAnalysis::ParsingTrace()
{
    VisualEffectRanking(traceStartPoint_, traceEndPoint_);
    if (!mapRsContainer_.empty()) {
        mapRsContainer_.erase(mapRsContainer_.begin());
    }
    InitdynamicEffectRsData();
    InitdynamicEffectFeData();
    SpCsvUtil::WriteCsv(rsDataCsv_, mapRsContainer_);
    SpCsvUtil::WriteCsv(feDataCsv_, mapFeContainer_);
}

void VisualEffectAnalysis::VisualEffectRanking(const std::string &beginStr, const std::string &overStr)
{
    std::string line;
    char fileName[PATH_MAX] = {0x00};
    if (realpath(tracePase_.c_str(), fileName) == nullptr) {
        LOGE("the file not exeit");
        return;
    }
    std::ifstream file(tracePase_);
    if (!file.is_open()) {
        LOGE("Unable to open file");
        return;
    }
    while (std::getline(file, line)) {
        if (!beginStr.empty() && line.find(beginStr) != std::string::npos && !beginTraceflag_) {
            beginTraceflag_ = true;
        }
        if (!overStr.empty() && line.find(overStr) != std::string::npos) {
            beginTraceflag_ = false;
            break;
        }
        if (beginStr.empty()) {
            beginTraceflag_ = true;
        }
        if (beginTraceflag_) {
            GetBeginTraceTime(line);
            GetRsLaneMap(line);
            GetFeLaneMap(line);
        }
    }
}

void VisualEffectAnalysis::GetBeginTraceTime(const std::string &line)
{
    if (line.find("#") == std::string::npos && fristLine_) {
        std::istringstream iss(line);
        std::string token;
        std::string timestamp;
        while (iss >> token) {
            if (token.find(":") != std::string::npos) {
                // 提取时间戳
                size_t pos = token.find(":");
                timestamp = token.substr(0, pos);
                break;
            }
        }
        double numResult = SPUtilesTye::StringToSometype<double>(timestamp);
        firstTraceTime_ = static_cast<long long>(std::round(numResult * oneMin_));
        fristLine_ = false;
    }
}
void VisualEffectAnalysis::GetRsLaneMap(const std::string &line)
{
    if (line.find("render_service") != std::string::npos
        && line.find ("OnReadablePerfCount-Ins") != std::string::npos) {
        dynamic_Effect_Rs_Data_["rsCpuCycle"] = GetCpuCycle(line);
        dynamic_Effect_Rs_Data_["timestamp"] = GetCutTime(line);
        dynamic_Effect_Rs_Data_["gpuLoad"] = std::to_string(gpuLoad_ / gpuLoadCollTimes_);
        dynamic_Effect_Rs_Data_["rdFps"] = std::to_string(rdFps_);
        PushPowerToMap();
        mapRsContainer_.push_back(dynamic_Effect_Rs_Data_);
        InitdynamicEffectRsData();
        rdFps_ = 0;
        gpuLoad_ = 0;
        gpuLoadCollTimes_ = 0;
    }
    GetGpuFre(line);
    GpuLoad(line);
    GetUtCpuCycle(line);
    GetCpuIdFre(line);
    GetDdrIdFre(line);
    GetRefreshRate(line);
    if (line.find("SceneAdapter::RenderFunction") != std::string::npos) {
        rdFps_ = 1;
    }
}

void VisualEffectAnalysis::GetFeLaneMap(const std::string &line)
{
    if (line.find("H:Waiting for Acquire Fence") != std::string::npos) {
        dynamic_Effect_Fe_Data_["timestamp"] = GetCutTime(line);
        dynamic_Effect_Fe_Data_["gpuCycle"] = std::to_string(gpuCycle_);
        dynamic_Effect_Fe_Data_["externalMemoryRead"] = std::to_string(externalMemoryReadRate_);
        dynamic_Effect_Fe_Data_["externalMemoryWrite"] = std::to_string(externalMemoryWriteRate_);
        dynamic_Effect_Fe_Data_["externalMemoryTraffic"] = std::to_string(externalMemoryTrafficRate_);
        mapFeContainer_.push_back(dynamic_Effect_Fe_Data_);
        InitdynamicEffectFeData();
        gpuCycle_ = 0;
        externalMemoryReadRate_ = 0;
        externalMemoryWriteRate_ = 0;
        externalMemoryTrafficRate_ = 0;
    }
    GetGpuCycle(line);
    GetExternalMemoryRead(line);
    GetexternalMemoryWrite(line);
    GetexternalMemoryTraffic(line);
}

void VisualEffectAnalysis::PushPowerToMap()
{
    int size = 0;
    if (!powerResult_.empty()) {
        size = static_cast<int>(powerResult_.size());
    }
    long long jittersTime = SPUtilesTye::StringToSometype<long long>(dynamic_Effect_Rs_Data_["timestamp"]);
    if (findTimeFlag_) {
        for (; i_ < size; i_++) {
            std::string powerTime = (powerResult_[i_])["powerTime"];
            powerTime_ = SPUtilesTye::StringToSometype<long long>(powerTime);
            if (jittersTime < powerTime_) {
                dynamic_Effect_Rs_Data_["currentNow"] = (powerResult_[i_])["currentNow"];
                dynamic_Effect_Rs_Data_["voltageNow"] = (powerResult_[i_])["voltageNow"];
                findTimeFlag_ = false;
                break;
            }
        }
    }
    if (jittersTime - powerTime_ > oneHundred_ && (i_ + 1) < size) {
        i_ += 1;
        std::string powerTime = (powerResult_[i_])["powerTime"];
        powerTime_ = SPUtilesTye::StringToSometype<long long>(powerTime);
        dynamic_Effect_Rs_Data_["currentNow"] = (powerResult_[i_])["currentNow"];
        dynamic_Effect_Rs_Data_["voltageNow"] = (powerResult_[i_])["voltageNow"];
    }
}

void VisualEffectAnalysis::GetGpuFre(const std::string &line)
{
    if (line.find("gpufreq-") != std::string::npos && line.find("gpufreq state") != std::string::npos) {
        size_t startPos = line.find("state=");
        if (startPos != std::string::npos) {
            size_t endPos = line.find(' ', startPos);
            if (endPos != std::string::npos) {
                std::string number = line.substr(startPos + 6, endPos - (startPos + 6));
                dynamic_Effect_Rs_Data_["gpuFrequency"] = number;
            }
        }
    }
}

void VisualEffectAnalysis::GpuLoad(const std::string &line)
{
    if (line.find("gpufreq-") != std::string::npos && line.find("gpuload state") != std::string::npos) {
        gpuLoadCollTimes_++;
        size_t startPos = line.find("state=");
        if (startPos != std::string::npos) {
            size_t endPos = line.find(' ', startPos);
            if (endPos != std::string::npos) {
                std::string number = line.substr(startPos + 6, endPos - (startPos + 6));
                gpuLoad_ += SPUtilesTye::StringToSometype<long long>(number);
            }
        }
    }
}

void VisualEffectAnalysis::GetUtCpuCycle(const std::string &line)
{
    if (line.find("RSUniRenderThre") != std::string::npos
        && line.find ("OnRenderFramePerfCount-Ins") != std::string::npos) {
        dynamic_Effect_Rs_Data_["utCpuCycle"] = GetCpuCycle(line);
    }
}

void VisualEffectAnalysis::GetRefreshRate(const std::string &line)
{
    if (dynamic_Effect_Rs_Data_["refreshRate"] == "0" && line.find("pendingRefreshRate") != std::string::npos) {
        size_t pos = line.find("pendingRefreshRate:");
        if (pos != std::string::npos) {
            pos += strlen("pendingRefreshRate: ");
            size_t endPos = line.find_first_not_of("0123456789", pos);
            if (endPos == std::string::npos) {
                endPos = line.length();
            }
            dynamic_Effect_Rs_Data_["refreshRate"] = line.substr(pos, endPos - pos);
        }
    }
}

void VisualEffectAnalysis::GetGpuCycle(const std::string &line)
{
    if (line.find("GPU Cycles") != std::string::npos) {
        size_t lastPipePos = line.rfind('|');
        if (lastPipePos != std::string::npos) {
            std::string numStr = line.substr(lastPipePos + 1);
            gpuCycle_ += SPUtilesTye::StringToSometype<long long>(numStr);
        }
    }
}

int VisualEffectAnalysis::GetClusterNum(const std::string &line)
{
    int cpu_id = 0;
    size_t pos = line.find("cpu_id=");
    if (pos != std::string::npos) {
        size_t start = pos + 7;
        size_t end = line.find(' ', start);
        if (end == std::string::npos) {
            end = line.length();
        }
        std::string cpu_id_str = line.substr(start, end - start);
        cpu_id = SPUtilesTye::StringToSometype<int>(cpu_id_str);
    }
    return cpu_id;
}

void VisualEffectAnalysis::GetCpuIdFre(const std::string &line)
{
    if (line.find("cpu_frequency:") != std::string::npos) {
        int cluster = GetClusterNum(line);
        GetCpuFre(line, cluster);
    }
}

void VisualEffectAnalysis::GetDdrIdFre(const std::string &line)
{
    if (line.find("ddr_cluster") != std::string::npos) {
        int cluster = GetClusterNum(line);
        GetDdrFre(line, cluster);
    }
}

void VisualEffectAnalysis::GetCpuFre(const std::string &line, const int &cluster)
{
    if (dynamic_Effect_Rs_Data_[cpuData_[cluster]] == "0") {
        std::size_t pos = line.find("state=");
        if (pos != std::string::npos) {
            size_t endPos = line.find(' ', pos);
            if (endPos != std::string::npos) {
                std::string valueStr = line.substr(pos + 6, endPos - (pos + 6));
                dynamic_Effect_Rs_Data_[cpuData_[cluster]] = valueStr;
            }
        }
    }
}

void VisualEffectAnalysis::GetDdrFre(const std::string &line, const int &cluster)
{
    if (dynamic_Effect_Rs_Data_[ddrData_[cluster]] == "0") {
        std::size_t pos = line.find("state=");
        if (pos != std::string::npos) {
            size_t endPos = line.find(' ', pos);
            if (endPos != std::string::npos) {
                const std::string valueStr = line.substr(pos + 6, endPos - (pos + 6));
                int ddrFre = SPUtilesTye::StringToSometype<int>(valueStr) * 1000;
                dynamic_Effect_Rs_Data_[ddrData_[cluster]] = std::to_string(ddrFre);
            }
        }
    }
}

std::string VisualEffectAnalysis::GetCutTime(const std::string &line)
{
    std::istringstream iss(line);
    std::string token;
    std::string timestamp;
    while (iss >> token) {
        if (token.find(":") != std::string::npos) {
            // 提取时间戳
            size_t pos = token.find(":");
            timestamp = token.substr(0, pos);
            break;
        }
    }
    double numResult = SPUtilesTye::StringToSometype<double>(timestamp);
    long long timeDiff = static_cast<long long>(std::round(numResult * 1000)) - firstTraceTime_;
    std::string curTime = std::to_string(beginCollTraceTime_ + timeDiff);
    return curTime;
}

std::string VisualEffectAnalysis::GetCpuCycle(const std::string &line)
{
    int cycleMark = 3;
    std::istringstream iss(line);
    std::string cpuCycle = "";
    for (int i = 0; i < cycleMark; i++) {
        std::getline(iss, cpuCycle, '|');
    }
    std::getline(iss, cpuCycle, '|');
    return cpuCycle;
}

void VisualEffectAnalysis::GetExternalMemoryRead(const std::string &line)
{
    if (line.find("External Memory Read") != std::string::npos && line.find("[KB]") != std::string::npos) {
        std::size_t pos = line.rfind("|");
        if (pos != std::string::npos) {
            std::string lastPart = line.substr(pos + 1);
            externalMemoryReadRate_ += SPUtilesTye::StringToSometype<long long>(lastPart);
        }
    }
}

void VisualEffectAnalysis::GetexternalMemoryWrite(const std::string &line)
{
    if (line.find("External Memory Write") != std::string::npos && line.find("[KB]") != std::string::npos) {
        std::size_t pos = line.rfind("|");
        if (pos != std::string::npos) {
            std::string lastPart = line.substr(pos + 1);
            externalMemoryWriteRate_ += SPUtilesTye::StringToSometype<long long>(lastPart);
        }
    }
}

void VisualEffectAnalysis::GetexternalMemoryTraffic(const std::string &line)
{
    if (line.find("External Memory Traffic") != std::string::npos && line.find("[KB]") != std::string::npos) {
        std::size_t pos = line.rfind("|");
        if (pos != std::string::npos) {
            std::string lastPart = line.substr(pos + 1);
            externalMemoryTrafficRate_ += SPUtilesTye::StringToSometype<long long>(lastPart);
        }
    }
}

void VisualEffectAnalysis::SetTraceTime(int &time)
{
    ftraceTime_ = time;
}

void VisualEffectAnalysis::SetTraceBegin(std::string &traceStartPoint)
{
    traceStartPoint_ = traceStartPoint;
}

void VisualEffectAnalysis::SetTraceEnd(std::string &traceEndPoint)
{
    traceEndPoint_ = traceEndPoint;
}
} // namespace SmartPerf
} // namespace OHOS