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

#ifndef GAME_EVENT_H
#define GAME_EVENT_H
#include "../interface/GameEventCallback.h"
#include "sp_profiler.h"
#include <string>

namespace OHOS {
namespace SmartPerf {
class GameEventCallbackImpl  : public GameEventCallback {
    public:
    GameEventCallbackImpl() {};
    void OnGameEvent(int32_t type, std::map<std::string, std::string> &params) override;
};

class GameEvent : public SpProfiler {
    public:
    std::map<std::string, std::string> ItemData() override;
    static GameEvent &GetInstance()
    {
        static GameEvent instance;
        return instance;
    }
    int RegisterGameEvent();
    int UnregisterGameEvent();
    void StartExecutionOnce(bool isPause) override;
    void FinishtExecutionOnce(bool isPause) override;
    std::map<std::string, std::string> &GetGameEventItemData();
    private:
    GameEvent() {};
    GameEvent(const GameEvent &) = delete;
    GameEvent &operator=(const GameEvent &) = delete;
    std::map<std::string, std::string> gameEventParams;
    std::map<std::string, std::string> gameEventItemData;
    const std::string gameEventParamPid = "pid";
    const std::string gameEventParamType = "functionType";
    const std::string createPlugin = "onCreatePlugin";
    bool isRegister = false;
};
} // namespace SmartPerf
} // namespace OHOS
#endif // GAME_EVENT_H