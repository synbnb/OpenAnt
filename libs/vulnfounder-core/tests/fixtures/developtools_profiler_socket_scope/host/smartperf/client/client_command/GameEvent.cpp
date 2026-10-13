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
#include "include/GameEvent.h"
#include "interface/GameServicePlugin.h"

#include <string>
#include <map>
#include "include/service_plugin.h"
#include <sp_log.h>
#include <dlfcn.h>
#include <memory>

namespace OHOS {
namespace SmartPerf {
void GameEventCallbackImpl::OnGameEvent(int32_t type, std::map<std::string, std::string> &params)
{
    for (auto &item : params) {
        GameEvent::GetInstance().GetGameEventItemData()[item.first] = item.second;
    }
}

std::map<std::string, std::string> GameEvent::ItemData()
{
    LOGI("GameEvent:ItemData map size(%u)", gameEventItemData.size());
    return gameEventItemData;
}

std::map<std::string, std::string> &GameEvent::GetGameEventItemData()
{
    return gameEventItemData;
}

void GameEvent::StartExecutionOnce(bool isPause)
{
    if (isPause) {
        return;
    }
    RegisterGameEvent();
}

void GameEvent::FinishtExecutionOnce(bool isPause)
{
    if (isPause) {
        return;
    }
    UnregisterGameEvent();
}

int GameEvent::RegisterGameEvent()
{
    if (isRegister) {
        WLOGI("GameEvent::RegisterGameEvent, already register");
        return 0;
    }
    WLOGI("GameEvent::RegisterGameEvent");
    std::unique_ptr<GameEventCallback> gameEventCallback = std::make_unique<GameEventCallbackImpl>();
    ServicePluginHandler &servicePluginHandler = ServicePluginHandler::GetInstance();
    void* handle = servicePluginHandler.GetSoHandler(ServicePluginHandler::ServicePluginType::GAME_PLUGIN);
    if (!handle) {
        WLOGE("Get service plugin handler failed.");
        return -1;
    }
    typedef GameServicePlugin *(*GetServicePlugin)();
    GetServicePlugin servicePlugin = (GetServicePlugin)dlsym(handle, createPlugin.c_str());
    if (!servicePlugin) {
        WLOGE("GameServicePlugin Error loading symbol");
        return -1;
    }

    int ret = servicePlugin()->RegisterGameEventListener(std::move(gameEventCallback));
    if (ret == 0) {
        isRegister = true;
        WLOGI("GameEvent::ItemData, RegisterGameEventListener success");
    } else {
        WLOGE("GameEvent::ItemData, RegisterGameEventListener failed");
    }
    return ret;
}

int GameEvent::UnregisterGameEvent()
{
    if (!isRegister) {
        return 0;
    }
    WLOGI("GameEvent::UnregisterGameEvent");
    ServicePluginHandler &servicePluginHandler = ServicePluginHandler::GetInstance();
    void* handle = servicePluginHandler.GetSoHandler(ServicePluginHandler::ServicePluginType::GAME_PLUGIN);
    if (!handle) {
        WLOGE("Get service plugin handler failed.");
        return -1;
    }
    typedef GameServicePlugin *(*GetServicePlugin)();
    GetServicePlugin servicePlugin = (GetServicePlugin)dlsym(handle, createPlugin.c_str());
    if (!servicePlugin) {
        WLOGE("GameServicePlugin Error loading symbol");
        return -1;
    }

    int ret = servicePlugin()->UnregisterGameEventListener();
    if (ret == 0) {
        isRegister = false;
        WLOGI("GameEvent::ItemData, UnregisterGameEventListener success");
    } else {
        WLOGE("GameEvent::ItemData, UnregisterGameEventListener failed");
    }
    return ret;
}

} // namespace SmartPerf
} // namespace OHOS