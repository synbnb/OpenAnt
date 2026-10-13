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
#ifndef BY_TRACE_H
#define BY_TRACE_H
#include "common.h"
#include <fstream>
#include "sp_profiler.h"
namespace OHOS {
namespace SmartPerf {
class ByTrace : public SpProfiler {
public:
    static ByTrace &GetInstance()
    {
        static ByTrace instance;
        return instance;
    }
    std::map<std::string, std::string> ItemData() override;
    // 校验fps-jitters
    void CheckFpsJitters(long long& jitters, int cfps);
    void SetByTrace();
    void ClearTraceFiles() const;
    void RemoveTraceFiles() const;
    void CpTraceFile() const;
    long long GetThreshold() const;
    int GetLowFps() const;
    void SendSurfaceCaton(long long& jitters, int cfps);
    static inline std::string jittersAndLowFps = "";
    static inline std::string hiviewTrace = "";
public:
    long long lastEnableTime = 0;
    std::string traceCpPath_ {"/data/local/tmp/hitrace"};
    long long nowTime = 0;
    int times = 0;
private:
    ByTrace() {};
    ByTrace(const ByTrace &);
    ByTrace &operator = (const ByTrace &);

    const std::string hiviewTracePath_ {"/data/log/hiview/unified_collection/trace/special/"};

    long long jitterTimesTaken = 0;
    int lowFps = -1;
};
}
}
#endif