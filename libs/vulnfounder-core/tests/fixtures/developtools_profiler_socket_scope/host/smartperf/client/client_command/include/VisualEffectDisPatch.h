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

#ifndef VISUAL_EFFECT_DISPATCH_H
#define VISUAL_EFFECT_DISPATCH_H

#include "../interface/GameScheduleEventCallBack.h"
#include "sp_profiler.h"
#include <string>

namespace OHOS {
namespace SmartPerf {
class GameScheduleEventCallbackImpl : public GameScheduleEventCallback {
    public:
    GameScheduleEventCallbackImpl() {};
    int32_t OnGameScheduleEvent(int32_t type, std::map<std::string, std::string> &params) override;
};

class VisualEffectDisPatch : public SpProfiler {
    public:
    std::map<std::string, std::string> ItemData() override;
    static VisualEffectDisPatch &GetInstance()
    {
        static VisualEffectDisPatch instance;
        return instance;
    }
    int RegisterGameScheduleEvent();
    int UnregisterGameEvent();
    void StartExecutionOnce(bool isPause) override;
    void FinishtExecutionOnce(bool isPause) override;
    std::map<std::string, std::string> &GetVisualEffectDisPatchItemData();
    void SetVisualEffectDisPatchType(int32_t type);
    void SetCollectNum();
    void SetSpeciFlag();
    void SetCatchTraceFlag();
    bool GetSpeciFlag();
    bool GetCatchTraceFlag();
    private:
    VisualEffectDisPatch() {};
    VisualEffectDisPatch(const VisualEffectDisPatch &) = delete;
    VisualEffectDisPatch &operator=(const VisualEffectDisPatch &) = delete;
    std::map<std::string, std::string> visualEffectDisPatchParams;
    std::map<std::string, std::string> visualEffectDisPatchItemData;
    int32_t type_ = 1;
    const std::string visualEffectDisPatchParamPid = "pid";
    const std::string visualEffectDisPatchParamType = "dispatchType";
    const std::string createPlugin = "onCreatePlugin";
    bool isRegister = false;
    bool speciFlag_ = false;
    bool catchTraceFlag_ = false;
    int32_t maxFileFlag_ = 5;
    int32_t captureFileFlag_ = 2;
};
} // namespace SmartPerf
} // namespace OHOS
#endif // VISUAL_EFFECT_DISPATCH_H
