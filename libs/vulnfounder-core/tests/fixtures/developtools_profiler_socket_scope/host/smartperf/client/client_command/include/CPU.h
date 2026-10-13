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
#ifndef CPU_H
#define CPU_H
#include <iostream>
#include <vector>
#include "sp_profiler.h"
namespace OHOS {
namespace SmartPerf {
struct CpuFreqs {
    uint32_t cpuId = 0;
    uint32_t curFreq = 0;
};
struct CpuUsageInfos {
    std::string cpuId;
    double userUsage = 0;
    double niceUsage = 0;
    double systemUsage = 0;
    double idleUsage = 0;
    double ioWaitUsage = 0;
    double irqUsage = 0;
    double softIrqUsage = 0;
};

class CPU : public SpProfiler {
public:
    static CPU &GetInstance()
    {
        static CPU instance;
        return instance;
    }
    std::map<std::string, std::string> ItemData() override;
    std::vector<CpuFreqs> GetCpuFreq();
    std::vector<CpuUsageInfos> GetCpuUsage();
    std::map<std::string, std::string> GetSysProcessCpuLoad();
    void GetSysProcessCpuLoadContinue(std::map<std::string, std::string> &processCpuInfo);
    void GetSysChildProcessCpuLoad(size_t processIdSize, std::map<std::string, std::string> &processCpuInfo) const;
    void SetPackageName(const std::string &pName);
    void SetProcessId(const std::string &pid);
    std::map<std::string, std::string> GetCpuCoreCurFreqs();
    void GetCpuFreqItemData(std::map<std::string, std::string> &cpuFreqResult);
    void GetCpuUsageItemData(std::map<std::string, std::string> &cpuUsageResult);
private:
    CPU() {};
    CPU(const CPU &);
    CPU &operator = (const CPU &);
    std::string packageName = "";
    std::vector<std::string> processId;
    const std::string cpustr = "cpu";
    const std::string totalcpu = "Totalcpu";
    int twenty = 20;
    int thousand = 1000;
};
}
}
#endif