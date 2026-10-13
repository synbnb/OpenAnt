/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef THREADS
#define THREADS
#include <sstream>
#include "sp_profiler.h"
namespace OHOS {
namespace SmartPerf {
class Threads : public SpProfiler {
public:
    std::map<std::string, std::string> ItemData() override;
    static Threads &GetInstance()
    {
        static Threads instance;
        return instance;
    }
   
    void SetPackageName(const std::string &pName);
    void SetProcessId(const std::string &pid);
    void SetProcessIdForFuzzTest(const std::vector<std::string> &pid);
private:
    Threads() {};
    Threads(const Threads &);
    Threads &operator = (const Threads &);
    std::string GetThreads(const std::string &pid, std::string &tid);
    std::string packageName = "";
    std::vector<std::string> processId;
};
}
}
#endif
