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
#ifndef RAM_H
#define RAM_H
#include "sp_profiler.h"
#include <future>
#include <string>

enum {
    RAM_ONE = 1,
    RAM_SECOND,
    RAM_THIRD,
    RAM_FOURTH,
    RAM_FIFTH,
    RAM_SIXTH,
    RAM_SEVENTH,
    RAM_EIGHTH,
    RAM_NINTH,
    RAM_TENTH,
};

struct PssValues {
    std::string gpuPssValue = "";
    std::string graphicPssValue = "";
    std::string arktsHeapPssValue = "";
    std::string nativeHeapPssValue = "";
    std::string stackPssValue = "";
    std::string anonPagePssValue = "";
    std::string filePagePssValue = "";
    std::string ashmemPssValue = "";
    std::string guardPssValue = "";
    std::string hapPssValue = "";
    std::string dbPssValue = "";
    std::string soPssValue = "";
    std::string devPssValue = "";
    std::string ttfPssValue = "";
};
namespace OHOS {
namespace SmartPerf {
class RAM : public SpProfiler {
public:
    std::map<std::string, std::string> GetSysRamInfo() const;
    std::map<std::string, std::string> GetRamInfo();
    std::map<std::string, std::string> GetPssRamInfo(FILE *fd, const std::string& pid, size_t index);
    std::map<std::string, std::string> ParsePssValues(FILE *fd, std::vector<std::string> &paramsInfo,
        const std::string pid, size_t index);
    void GetPssAboutPid(struct PssValues &pss, std::vector<std::string> &params);
    void GetDevecoPssAboutPid(struct PssValues &pss, std::vector<std::string> &params);
    void FillPssRamInfo(size_t index, std::string pid, const PssValues &pssValues,
        std::map<std::string, std::string> &pssRamInfo) const;
    std::map<std::string, std::string> SaveSumRamInfo(std::vector<std::string>& paramsInfo,
        const std::string& pid, size_t index) const;
    std::map<std::string, std::string> ProcMemNaInfo() const;
    std::map<std::string, std::string> ChildProcMemNaInfo() const;
    void SetRamValue(std::promise<std::map<std::string, std::string>> p, std::string ramPid, size_t index);
    std::map<std::string, std::string> CollectRam(const std::string& ramPid, size_t index);
    std::future<std::map<std::string, std::string>> AsyncCollectRam(const std::string& ramPid, size_t index);
    void CheckFutureRam(std::future<std::map<std::string, std::string>> &fdsResult,
        std::map<std::string, std::string> &dataMap, const std::string& pid, size_t index) const;
    static RAM &GetInstance()
    {
        static RAM instance;
        return instance;
    }
    std::map<std::string, std::string> ItemData() override;
    void SetPackageName(const std::string &pName);
    void ThreadGetPss();
    void TriggerGetPss();
    void SetFirstFlag();
    void SetHapFirstFlag();
    void SetProcessId(const std::string &pid);
private:
    RAM() {};
    RAM(const RAM &);
    RAM &operator = (const RAM &);
    std::string packageName = "";
    std::vector<std::string> processId;
    std::map<std::string, std::string> result = {};
};
}
}
#endif
