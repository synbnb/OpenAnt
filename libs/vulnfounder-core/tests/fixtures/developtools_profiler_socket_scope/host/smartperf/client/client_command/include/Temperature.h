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
#ifndef TEMPERATURE_H
#define TEMPERATURE_H

#include <vector>
#include "sp_profiler.h"
namespace OHOS {
namespace SmartPerf {
class Temperature : public SpProfiler {
public:
    std::vector<std::string> collectNodes = { std::string("soc_thermal"), std::string("system_h"),
                                              std::string("soc-thermal"), std::string("gpu"),
                                              std::string("shell_frame"), std::string("shell_front"),
                                              std::string("shell_back"),  std::string("Battery"),
                                              std::string("cluster0"), std::string("gpu-thermal"),
                                              std::string("drmos_gpu_npu"), std::string("npu_thermal")};
    std::map<std::string, std::string> ItemData() override;
    static Temperature &GetInstance()
    {
        static Temperature instance;
        return instance;
    }
    void GetTempInfos(std::map<std::string, std::string> &result, const std::string& type, const std::string& temp);

private:
    Temperature() {};
    Temperature(const Temperature &);
    Temperature &operator = (const Temperature &);
    std::string thermalBasePath = "/sys/class/thermal";
};
}
}
#endif