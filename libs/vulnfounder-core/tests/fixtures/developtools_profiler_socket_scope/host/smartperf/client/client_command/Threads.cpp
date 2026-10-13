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
#include "cpu_collector.h"
#include "collect_result.h"
#include "include/common.h"
#include "include/sp_utils.h"
#include "include/sp_log.h"
#include "include/Threads.h"

using namespace OHOS::HiviewDFX;
using namespace OHOS::HiviewDFX::UCollectUtil;
using namespace OHOS::HiviewDFX::UCollect;
namespace OHOS {
namespace SmartPerf {
std::string Threads::GetThreads(const std::string &pid, std::string &tid)
{
    std::shared_ptr<CpuCollector> collector = CpuCollector::Create();
    auto threadCollector = collector->CreateThreadCollector(SPUtilesTye::StringToSometype<int>(pid));
    auto collectResult = threadCollector->CollectThreadStatInfos(false);
    if (collectResult.retCode == UcError::SUCCESS) {
        size_t cnt = collectResult.data.size();
        for (size_t i = 0; i < cnt; i++) {
            if (i < cnt - 1) {
                tid.append(std::to_string(collectResult.data[i].tid)).append(" ");
            } else {
                tid.append(std::to_string(collectResult.data[i].tid));
            }
        }
        return std::to_string(cnt);
    } else {
#ifndef FUZZ_TEST
        processId.erase(std::remove(processId.begin(), processId.end(), pid), processId.end());
        LOGD("Collect thread info fail (%d)", collectResult.retCode);
#endif
        return "";
    }
}

std::map<std::string, std::string> Threads::ItemData()
{
    std::map<std::string, std::string> result;
    std::string& threadsNum = result["threadsNum"];
    std::string& tids = result["tids"];
    size_t idNum = processId.size();
    for (size_t i = 0; i < idNum; i++) {
        std::string tid = "";
        std::string num = GetThreads(processId[i], tid);
        threadsNum.append(processId[i]).append(":").append(num);
        tids.append(processId[i]).append(":").append(tid);
        if (idNum > 1) {
            threadsNum.append("|");
            tids.append("|");
        }
    }
    return result;
}

void Threads::SetPackageName(const std::string &pName)
{
    packageName = pName;
}

void Threads::SetProcessId(const std::string &pid)
{
    processId.clear();
    SPUtils::StrSplit(pid, " ", processId);
}

void Threads::SetProcessIdForFuzzTest(const std::vector<std::string> &pid)
{
    processId = pid;
}
}
}