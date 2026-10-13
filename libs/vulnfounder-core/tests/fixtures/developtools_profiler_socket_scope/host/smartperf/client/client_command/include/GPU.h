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

#ifndef GPU_H
#define GPU_H
#include <vector>
#include "sp_profiler.h"
namespace OHOS {
namespace SmartPerf {
class GPU : public SpProfiler {
public:
    std::map<std::string, std::string> ItemData() override;
    static GPU &GetInstance()
    {
        static GPU instance;
        return instance;
    }
    int GetGpuFreq();
    float GetGpuLoad();
    int32_t GetRkGpuFreq();
    float GetRkGpuLoad();
    void SetRkFlag();

private:
    GPU() {};
    GPU(const GPU &);
    GPU &operator = (const GPU &);
    bool rkFlag = false;
};
}
}
#endif // GPU_H
