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

#ifndef CPU_INFO_H
#define CPU_INFO_H

#include "sp_profiler.h"
#include "sp_utils.h"
#include <string>
#include <vector>
#include <thread>
#include <fstream>
#include <atomic>
#include <condition_variable>

namespace OHOS {
namespace SmartPerf {
class CPUInfo : public SpProfiler {
public:
    static CPUInfo &GetInstance()
    {
        static CPUInfo instance;
        return instance;
    }
    std::map<std::string, std::string> ItemData() override;
    void StartExecutionOnce(bool isPause) override;
    void FinishtExecutionOnce(bool isPause) override;
    void SetPids(const std::string& pids);
    void Start();
    void Stop();
private:
    void CalculateCPIInfo(const std::string line, double &cpiTotal, size_t &cpiCount);
    std::vector<std::string> pids_;
    std::thread th_;
    std::string hiperfCmd_ = "/bin/hiperf stat -e " + SPUtils::GetProductName() + "-instructions," +
    SPUtils::GetProductName() + "-cpu-cycles -d 1 -i 500 ";
    std::atomic_bool running_ {false};
    std::condition_variable cond_;
    std::mutex mtx_;
    std::string buffer_;
};
}
}
#endif // CPU_INFO_H