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
#ifndef SP_PROFILER_FACTORY_H
#define SP_PROFILER_FACTORY_H
#include "common.h"
#include "sp_profiler.h"
namespace OHOS {
namespace SmartPerf {
class SpProfilerFactory {
public:
    static SpProfiler *GetProfilerItem(MessageType messageType);
    static SpProfiler *GetProfilerItemContinue(MessageType messageType);
    static void SetProfilerPkg(const std::string &pkg);
    static void SetProfilerPidByPkg(std::string &pid, std::string pids = "");
    static SpProfiler *GetCmdProfilerItem(CommandType commandType, bool cmdFlag);
    static SpProfiler *GetCmdProfilerItemOption(CommandType commandType, bool cmdFlag);
    static SpProfiler *GetCmdProfilerItemContinue(CommandType commandType, bool cmdFlag);
    static inline bool editorFlag = false;
};
}
}
#endif