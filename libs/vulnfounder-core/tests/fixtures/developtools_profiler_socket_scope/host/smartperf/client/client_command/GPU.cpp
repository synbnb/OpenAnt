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
#include "include/GPU.h"
#include <iostream>
#include "include/sp_utils.h"
#include "gpu_collector.h"
#include "collect_result.h"
#include "include/sp_log.h"

using namespace OHOS::HiviewDFX;
using namespace OHOS::HiviewDFX::UCollectUtil;
using namespace OHOS::HiviewDFX::UCollect;

namespace OHOS {
namespace SmartPerf {
std::map<std::string, std::string> GPU::ItemData()
{
    std::map<std::string, std::string> result;
    int32_t freq;
    float load;
    if (!rkFlag) {
        freq = GetGpuFreq();
        load = GetGpuLoad();
    } else {
        freq = GetRkGpuFreq();
        load = GetRkGpuLoad();
    }
    result["gpuFrequency"] = std::to_string(freq);
    result["gpuLoad"] = std::to_string(load);
    if (result.find("gpuFrequency") != result.end() && result["gpuFrequency"].empty()) {
        result["gpuFrequency"] = "NA";
        result["gpuLoad"] = "NA";
    }

    LOGI("GPU:ItemData map size(%u)", result.size());
    return result;
}

int GPU::GetGpuFreq()
{
    std::shared_ptr<GpuCollector> collector = GpuCollector::Create();
    CollectResult<GpuFreq> result = collector->CollectGpuFrequency();
    return result.data.curFeq;
}

float GPU::GetGpuLoad()
{
    std::shared_ptr<GpuCollector> collector = GpuCollector::Create();
    CollectResult<SysGpuLoad> result = collector->CollectSysGpuLoad();
    return float(result.data.gpuLoad);
}

int32_t GPU::GetRkGpuFreq()
{
    const std::string gpuFreqPath = "/sys/class/devfreq/fde60000.gpu/cur_freq";
    std::string rkFreq;
    SPUtils::LoadFile(gpuFreqPath, rkFreq);
    return SPUtilesTye::StringToSometype<int32_t>(rkFreq);
}

float GPU::GetRkGpuLoad()
{
    const std::string gpuLoadPath = "/sys/class/devfreq/fde60000.gpu/load";
    std::string rkLoad;
    SPUtils::LoadFile(gpuLoadPath, rkLoad);
    size_t len = rkLoad.length();
    if (len > 0) {
        rkLoad = rkLoad.substr(0, len - 1);
    }
    return SPUtilesTye::StringToSometype<float>(rkLoad);
}

void GPU::SetRkFlag()
{
    rkFlag = true;
}
}
}
