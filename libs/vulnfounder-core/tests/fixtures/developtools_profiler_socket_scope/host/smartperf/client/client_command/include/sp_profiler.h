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
#ifndef SP_PROFILER_H
#define SP_PROFILER_H
#include <map>
namespace OHOS {
namespace SmartPerf {
class SpProfiler {
public:
    SpProfiler() {};
    virtual ~SpProfiler() {};
    virtual std::map<std::string, std::string> ItemData() = 0;
    virtual void StartExecutionOnce(bool isPause) {};
    virtual void FinishtExecutionOnce(bool isPause) {};
    std::function<void(std::string)> ipcCallback_ {nullptr};
};
}
}
#endif