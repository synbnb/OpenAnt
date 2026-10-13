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
#ifndef JITTERS_H
#define JITTERS_H
#include <vector>
#include <queue>
#include "sp_profiler.h"
namespace OHOS {
namespace SmartPerf {
struct JittersInfo {
    std::vector<long long> jitters;
    std::vector<long long> currTimeStamps;
    std::vector<long long> currDumpTimeStamps;
    int curTime;
    int fps;
    void Clear()
    {
        fps = 0;
        curTime = 0;
        jitters.clear();
    }
    bool operator == (const JittersInfo &other) const
    {
        if (fps != other.fps) {
            return false;
        }
        if (jitters.size() != other.jitters.size()) {
            return false;
        }
        for (size_t i = 0; i < jitters.size(); i++) {
            if (jitters[i] != other.jitters[i]) {
                return false;
            }
        }
        return true;
    }
    JittersInfo()
    {
        fps = 0;
        curTime = 0;
    }
};

class Jitters : public SpProfiler {
public:
    static Jitters &GetInstance()
    {
        static Jitters instance;
        return instance;
    }
    std::map<std::string, std::string> ItemData() override;
    void StartExecutionOnce(bool isPause) override;
    void SetPackageName(const std::string& pName);
    void SetProcessId(const std::string &pid);
    JittersInfo jittersInfo;
    JittersInfo jittersInfoData;
    JittersInfo prevResultFpsInfo;
    JittersInfo GetJittersInfo();
    JittersInfo GetJittersByDump(const std::string& name);
    void CalcJitters();
    bool CalcFpsAndJitters(bool isBreak);
    long long CalculateJitter() const;
    bool isGameApp = false;

private:
    Jitters() {};
    Jitters(const Jitters &);
    Jitters &operator = (const Jitters &);

    long long mod = 1e9;
    long long curScreenTimestamp = 0;
    long long prevScreenTimestamp = -1;
    long long prevlastScreenTimestamp = 0;
    int fpsNum = 0;
    std::string pkgName = "";
    std::string processId = "";
};
}
}
#endif