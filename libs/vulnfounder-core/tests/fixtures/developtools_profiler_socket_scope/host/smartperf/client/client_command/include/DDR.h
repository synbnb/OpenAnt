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
#ifndef DDR_H
#define DDR_H
#include "sp_profiler.h"
namespace OHOS {
namespace SmartPerf {
class DDR : public SpProfiler {
public:
    long long GetDdrFreq();
    static DDR &GetInstance()
    {
        static DDR instance;
        return instance;
    }
    std::map<std::string, std::string> ItemData() override;
    void SetRkFlag();

private:
    DDR() {};
    DDR(const DDR &);
    DDR &operator = (const DDR &);
    std::string ddrCurFreqPath = "/sys/class/devfreq/ddrfreq/cur_freq";
    std::string ddrCurFreqRkPath = "/sys/class/devfreq/fde60000.gpu/available_frequencies";
    bool rkFlag = false;
};
};
}
#endif
