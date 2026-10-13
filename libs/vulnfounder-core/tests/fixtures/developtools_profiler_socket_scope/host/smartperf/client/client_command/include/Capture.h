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
#ifndef CAPTURE_H
#define CAPTURE_H
#include "sp_profiler.h"
namespace OHOS {
namespace SmartPerf {
class Capture : public SpProfiler {
public:
    std::map<std::string, std::string> ItemData() override;
    static Capture &GetInstance()
    {
        static Capture instance;
        return instance;
    }
    // 截图线程
    void ThreadGetCatch();
    void ThreadGetCatchSocket();
    // 触发线程
    void TriggerGetCatch();
    void TriggerGetCatchSocket();
    bool TakeScreenCap(const std::string &savePath) const;
    void SetCollectionNum();
    long long GetCurTimes();
    void SocketMessage();
private:
    Capture() {};
    Capture(const Capture &);
    Capture &operator = (const Capture &);
    bool isSocketMessage = false;
    int callNum = 0;
    long long curTime = 0.0;
};
}
}
#endif