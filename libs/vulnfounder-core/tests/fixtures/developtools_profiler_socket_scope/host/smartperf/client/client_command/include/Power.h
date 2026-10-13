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
#ifndef POWER_H
#define POWER_H
#include <sstream>
#include "sp_profiler.h"
namespace OHOS {
namespace SmartPerf {
class Power : public SpProfiler {
public:
    std::map<std::string, std::string> ItemData() override;
    static Power &GetInstance()
    {
        static Power instance;
        return instance;
    }
    void SetRkFlag();

private:
    Power() {};
    Power(const Power &);
    Power &operator = (const Power &);
    const std::string currentNowPath = "/sys/class/power_supply/Battery/current_now";
    const std::string voltageNowPath = "/sys/class/power_supply/Battery/voltage_now";
    const std::string batteryNumPath = "sys/class/power_supply/Battery/serial_count";
    bool rkFlag = false;
};
}
}
#endif
