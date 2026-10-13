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

#ifndef HIPERF_H
#define HIPERF_H
#include "common.h"
#include <string>
#include "mutex"
#include "vector"
#include <map>
#include "sp_profiler.h"
#include "sp_utils.h"
namespace OHOS {
namespace SmartPerf {
class Hiperf : public SpProfiler {
public:
    std::map<std::string, std::string> ItemData() override;
    static Hiperf &GetInstance()
    {
        static Hiperf instance;
        return instance;
    }
    void StartExecutionOnce(bool isPause) override;
    void FinishtExecutionOnce(bool isPause) override;
    void SetProcessId(const std::string &pid);
    void PrepareHiperf();
    void StartHiperf();
    void StopHiperf();
    void GetHiperfData();
    void SetDataMap(std::string &line);
    std::string ReturnHiperfData();
    std::string ProcessCountData(std::string count);

private:
    Hiperf() {};
    Hiperf(const Hiperf &);
    Hiperf &operator = (const Hiperf &);
    const std::string savePath_ = "data/local/tmp/test.txt";
    std::string processId_;
    std::mutex hiperfLock_;
    std::map<std::string, std::string> hiperfData_ = {};
    const std::string cpuCycles = SPUtils::GetProductName() + "-cpu-cycles";
    const std::string inStructions = SPUtils::GetProductName() + "-instructions";
    std::vector<std::string> collectNodes_ = {cpuCycles, inStructions};
    bool hiperfFirstCollect_ = true;
};
}
}
#endif // HIPERF_H
