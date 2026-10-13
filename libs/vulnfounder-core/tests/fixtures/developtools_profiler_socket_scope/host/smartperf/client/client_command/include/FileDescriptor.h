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
#ifndef FILEDRECRIOTOR
#define FILEDRECRIOTOR
#include <sstream>
#include "sp_profiler.h"
namespace OHOS {
namespace SmartPerf {
class FileDescriptor : public SpProfiler {
public:
    std::map<std::string, std::string> ItemData() override;
    static FileDescriptor &GetInstance()
    {
        static FileDescriptor instance;
        return instance;
    }

    void GetFds(const std::string &pid, std::string &fds, std::string &fdTotal);
    void SetPackageName(const std::string &pName);
    void SetProcessId(const std::string &pid);
    void SetProcessIdForFuzzTest(const std::vector<std::string> &pid);
private:
    FileDescriptor() {};
    FileDescriptor(const FileDescriptor &);
    FileDescriptor &operator = (const FileDescriptor &);
    bool rkFlag = false;
    std::string packageName = "";
    std::vector<std::string> processId;
    size_t idNum = 0;
};
}
}
#endif
