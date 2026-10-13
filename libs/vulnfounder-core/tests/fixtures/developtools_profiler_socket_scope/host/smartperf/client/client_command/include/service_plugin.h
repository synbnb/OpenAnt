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

#ifndef SERVICE_PLUGIN_H
#define SERVICE_PLUGIN_H

#include "string"
#include "map"
#include "thread"
#include "sp_profiler.h"

namespace OHOS {
    namespace SmartPerf {
        class ServicePluginHandler : public SpProfiler {
        public:
            enum ServicePluginType {
                GAME_PLUGIN,
                TEST_PLUGIN,
                PERF_GENIUS_PLUGIN,
                SCHEDULE_PLUGIN,
                PLUGIN_COUNT
            };

            std::map<std::string, std::string> ItemData() override;
            static ServicePluginHandler &GetInstance()
            {
                static ServicePluginHandler instance;
                return instance;
            }
            void* GetSoHandler(enum ServicePluginType type);

        private:
            ServicePluginHandler();
            ~ServicePluginHandler() override;
            ServicePluginHandler(const ServicePluginHandler &);
            ServicePluginHandler &operator = (const ServicePluginHandler &);

            const std::vector<std::string> pluginSoPath = {
                "/system/lib64/libgameservice_gpucounter_plugin.z.so",
                "/system/lib64/libtest_server_client.z.so",
                "/system/lib64/libperfgenius_client.z.so",
                "/system/lib64/libGameDftPlugin.so"
            };
            std::vector<void*> pluginHandle;
        };
    }
}

#endif