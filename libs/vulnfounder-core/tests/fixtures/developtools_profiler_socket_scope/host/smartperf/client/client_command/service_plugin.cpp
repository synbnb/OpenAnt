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
#include "string"
#include "map"
#include "thread"
#include <dlfcn.h>
#include "include/service_plugin.h"
#include "include/sp_log.h"

namespace OHOS {
    namespace SmartPerf {
        ServicePluginHandler::ServicePluginHandler()
        {
            pluginHandle.resize(PLUGIN_COUNT, nullptr);
        }
        ServicePluginHandler::~ServicePluginHandler()
        {
            for (int i = 0; i < PLUGIN_COUNT; i++) {
                if (pluginHandle[i] != nullptr) {
                    dlclose(pluginHandle[i]);
                    pluginHandle[i] = nullptr;
                }
            }
        }

        std::map<std::string, std::string> ServicePluginHandler::ItemData()
        {
            return std::map<std::string, std::string>();
        }

        void* ServicePluginHandler::GetSoHandler(enum ServicePluginType type)
        {
            if (pluginHandle[type] == nullptr) {
                char soFilePathChar[PATH_MAX] = {0x00};
                if ((realpath(pluginSoPath[type].c_str(), soFilePathChar) == nullptr)) {
                    WLOGE("%s is not exist.", pluginSoPath[type].c_str());
                    return nullptr;
                }

                pluginHandle[type] = dlopen(soFilePathChar, RTLD_LAZY);
                if (!pluginHandle[type]) {
                    WLOGE("open ServicePlugin so file error.");
                    return nullptr;
                }
            }
            return pluginHandle[type];
        }
    }
}