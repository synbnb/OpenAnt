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
#include "AI_schedule.h"
#include "interface/GameServicePlugin.h"
#include <string>
#include <map>
#include <service_plugin.h>
#include <sp_log.h>
#include <dlfcn.h>


namespace OHOS {
namespace SmartPerf {
std::map<std::string, std::string> AISchedule::ItemData()
{
    if (processId.empty()) {
        WLOGE("AISchedule need processId.");
        return std::map<std::string, std::string>();
    }
    aiScheduleParams[aiScheduleParamPid] = processId;
    aiScheduleParams[aiScheduleParamType] = "1";
    ServicePluginHandler &servicePluginHandler = ServicePluginHandler::GetInstance();

    void* handle = servicePluginHandler.GetSoHandler(ServicePluginHandler::ServicePluginType::GAME_PLUGIN);
    if (handle == nullptr) {
        WLOGE("Get service plugin handler failed.");
        return std::map<std::string, std::string>();
    }

    typedef GameServicePlugin *(*GetServicePlugin)();
    GetServicePlugin servicePlugin = (GetServicePlugin)dlsym(handle, createPlugin.c_str());
    if (!servicePlugin) {
        WLOGE("GameServicePlugin Error loading symbol");
        return std::map<std::string, std::string>();
    }
    return servicePlugin()->GetSystemFunctionStatus(aiScheduleParams);
}

void AISchedule::SetProcessId(const std::string &pid)
{
    processId = pid;
}
} // namespace SmartPerf
} // namespace OHOS