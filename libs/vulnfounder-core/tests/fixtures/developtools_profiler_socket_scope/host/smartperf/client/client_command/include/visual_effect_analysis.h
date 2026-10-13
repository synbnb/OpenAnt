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

#ifndef VISUAL_EFFECT_ANALYSIS_H
#define VISUAL_EFFECT_ANALYSIS_H
#include <sstream>
#include <vector>
#include <map>
#include "sp_data.h"
#include "mutex"
namespace OHOS {
namespace SmartPerf {
class VisualEffectAnalysis {
public:
    static VisualEffectAnalysis &GetInstance()
    {
        static VisualEffectAnalysis instance;
        return instance;
    }

    void InitIndexInfo();
    void GetDeviceCpuNum();
    void GetDeviceDdrNum();
    void InitdynamicEffectRsData();
    void InitdynamicEffectFeData();
    void CapturingTraces();
    void GetCyclePower();
    void ParsingTrace();
    void VisualEffectRanking(const std::string &beginStr, const std::string &overStr);
    void GetBeginTraceTime(const std::string &line);
    void GetRsLaneMap(const std::string &line);
    void GetFeLaneMap(const std::string &line);
    void PushPowerToMap();
    void GetGpuFre(const std::string &line);
    void GpuLoad(const std::string &line);
    void GetUtCpuCycle(const std::string &line);
    void GetRefreshRate(const std::string &line);
    void GetGpuCycle(const std::string &line);
    int GetClusterNum(const std::string &line);
    void GetCpuIdFre(const std::string &line);
    void GetDdrIdFre(const std::string &line);
    void GetCpuFre(const std::string &line, const int &cluster);
    void GetDdrFre(const std::string &line, const int &cluster);
    std::string GetCutTime(const std::string &line);
    std::string GetCpuCycle(const std::string &line);
    void GetExternalMemoryRead(const std::string &line);
    void GetexternalMemoryWrite(const std::string &line);
    void GetexternalMemoryTraffic(const std::string &line);
    void SetTraceTime(int &time);
    void SetTraceBegin(std::string &traceStartPoint);
    void SetTraceEnd(std::string &traceEndPoint);
private:
    VisualEffectAnalysis() {};
    VisualEffectAnalysis(const VisualEffectAnalysis &);
    VisualEffectAnalysis &operator = (const VisualEffectAnalysis &);
    std::vector <std::string> cpuData_ = {};
    std::vector <std::string> ddrData_ = {};
    std::map <std::string, std::string> dynamic_Effect_Rs_Data_ = {};
    std::map <std::string, std::string> dynamic_Effect_Fe_Data_ = {};
    std::map <std::string, std::string> powerMap_ = {};
    std::vector <std::map <std::string, std::string>> powerResult_;
    std::vector <std::map <std::string, std::string>> mapRsContainer_;
    std::vector <std::map <std::string, std::string>> mapFeContainer_;
    long long unixTime_ = 0;
    std::string rsDataCsv_ = "/t_index_info.csv";
    std::string feDataCsv_ = "/t_gpu_info.csv";
    const std::string getCpuNumCmd_ = "/proc/cpuinfo | grep processor | wc -l";

    const std::string ddrClusterPath_ = "/sys/devices/system/cpu/cpufreq/";
    const std::string countersGather_ = "./mnt/lower/vendor/bin/counters_gather -s 10";
    const std::string endFtrace_ = "hitrace --trace_finish_nodump";
    const std::string geginFtrace_ = "hitrace --trace_begin -b 512000 graphic ohos ace sched "
        "window freq multimodalinput zimage zmedia zcamera zaudio nweb app ark";
    int ftraceTime_ = 5000;
    int oneMin_ = 1000;
      // const std::string overtrace_ = "hitrace --trace_finish -o /data/local/tmp/smartperf/1/tmp.ftrace";
    const std::string overtrace_ = "hitrace --trace_finish -o /data/local/tmp/tmp.ftrace";
    const long long oneHundred_ = 100;
    // const std::string tracePase_ = "data/local/tmp/smartperf/1/tmp.ftrace";
    const std::string tracePase_ = "data/local/tmp/tmp.ftrace";
    bool smartPerfFlag_ = false;
    bool daForMeMaterFlag_ = false;
    bool beginTraceflag_ = false;
    bool findTimeFlag_ = true;
    int rdFps_ = 0;
    long long gpuLoad_ = 0;
    long long gpuCycle_ = 0;
    long long powerTime_ = 0;
    int i_ = 0;
    int gpuLoadCollTimes_ = 0;
    long long externalMemoryReadRate_ = 0;
    long long externalMemoryWriteRate_ = 0;
    long long externalMemoryTrafficRate_ = 0;
    std::mutex mtx_;
    std::string traceStartPoint_ = "";
    std::string traceEndPoint_ = "";
    long long beginCollTraceTime_ = 0;
    long long firstTraceTime_ = 0;
    bool fristLine_ = true;
};
} // namespace SmartPerf
} // namespace OHOS
#endif // VISUAL_EFFECT_ANALYSIS_H