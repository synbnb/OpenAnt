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
#ifndef PARSE_RADAR_H
#define PARSE_RADAR_H
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
namespace OHOS {
namespace SmartPerf {
class ParseRadar {
public:
    double ParseRadarResponse(const std::string &string) const;
    double ParseRadarDelayTime(const std::string &string, const std::string &target, const int &delayTime) const;
    std::string ParseRadarAppStrart(const std::string &string) const;
    double ParseRadarComplete(const std::string &string) const;
    std::string ExtractString(const std::string &str, const std::string &target) const;
    std::string ParseRadarFrame(const std::string &string) const;
    std::string ParseRadarMaxFrame(const std::string &string) const;
    int GetMaxDelayTime(const int &delayTime, std::vector<std::string> &delayTimeVec) const;
private:
    const int delayTimeResponse = 2000;
    const int delayTimeComplete = 2500;
    const std::string targetResponse = "\"RESPONSE_LATENCY\"";
    const std::string targetComplete = "\"E2E_LATENCY\"";
};
}
}
#endif // PARSE_RADAR_H