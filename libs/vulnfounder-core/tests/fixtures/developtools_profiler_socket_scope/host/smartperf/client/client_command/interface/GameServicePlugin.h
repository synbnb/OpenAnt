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
#ifndef GAME_SERVICE_PLUGIN_H
#define GAME_SERVICE_PLUGIN_H

#include <string>
#include <map>
#include "GameEventCallback.h"
#include "GpuCounterCallback.h"

namespace OHOS {
    namespace SmartPerf {
        class GameServicePlugin {
        public:
            uint32_t version;
            const char *pluginName;

            virtual int32_t StartGetGpuPerfInfo(int64_t duration, int64_t collectDur,
                std::unique_ptr <GpuCounterCallback> callback) = 0;
            virtual int32_t StopGetGpuPerfInfo() = 0;
            virtual std::map<std::string, std::string> GetSystemFunctionStatus(
                std::map<std::string, std::string> &queryParams) = 0;
            virtual int32_t RegisterGameEventListener(std::unique_ptr<GameEventCallback> callback) = 0;
            virtual int32_t UnregisterGameEventListener() = 0;
        };
    }
}
#endif