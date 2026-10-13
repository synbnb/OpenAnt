/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
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
#ifndef PARSESLIDEFPSTRACE_H
#define PARSESLIDEFPSTRACE_H
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

namespace OHOS {
namespace SmartPerf {
class ParseSlideFpsTrace {
public:
    double ParseSlideFpsTraceNoh(const std::string& file);
    double CalculateTime();
    std::string GetLineTime(const std::string& lineStr) const;
    std::string CutString(const std::string& lineStr, const std::string &start,
        const std::string &end, size_t offset) const;
    void AppSwiperScroll(const std::string& line);
private:
    std::ifstream infile;
    bool needTime = false;
    int frameNum = 0;
    int frameNow = 0;
    int count = 0;
    int four = 4;
    double touchTime = 0;
    double responseTime = 0;
    double doCompositionTime = 0;
    double completionTime = 0.035;
    double completeTime = 0;
    int swiperScrollFlag = 0;
    int swiperFlingFlag = 0;
    int listFlag = 0;
};
}
}
#endif // SMARTPERF_COMMAND_H