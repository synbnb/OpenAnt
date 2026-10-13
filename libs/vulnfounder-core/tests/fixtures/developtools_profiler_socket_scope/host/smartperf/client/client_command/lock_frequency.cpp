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

#include "include/lock_frequency.h"
#include <thread>
#include <chrono>
#include <dlfcn.h>
#include "include/sp_log.h"
#include "include/service_plugin.h"

namespace OHOS {
namespace SmartPerf {
    std::map<std::string, std::string> LockFrequency::ItemData()
    {
        return std::map<std::string, std::string>();
    }
    void LockFrequency::LockingThread()
    {
        LOGD("Lock frequency thread create");
        const int loopLockTime = 4000;

        ServicePluginHandler &servicePluginHandler = ServicePluginHandler::GetInstance();
        void* handle = servicePluginHandler.GetSoHandler(ServicePluginHandler::ServicePluginType::TEST_PLUGIN);
        if (!handle) {
            WLOGE("open TestServerPlugin so file error.");
            return;
        }

        typedef int32_t (*GetLockFreq)();
        GetLockFreq testServerPlugin = (GetLockFreq)dlsym(handle, lockFunction.c_str());
        if (!testServerPlugin) {
            WLOGE("Error loading symbol");
            return;
        }
        while (isCollecting) {
            testServerPlugin();
            std::this_thread::sleep_for(std::chrono::milliseconds(loopLockTime));
        }

        LOGD("Lock frequency thread end");
    }

    void LockFrequency::StartExecutionOnce(bool isPause)
    {
        if (isPause) {
            return;
        }
        SetIsCollecting(true);
        th_ = std::thread([this]() {
            WLOGI("Starting lock frequency locking thread");
            LockingThread();
        });
    }

    void LockFrequency::FinishtExecutionOnce(bool isPause)
    {
        if (isPause) {
            return;
        }
        SetIsCollecting(false);
        if (th_.joinable()) {
            LOGD("Joining lockFreqThread.");
            th_.join();
        }
    }

    void LockFrequency::SetIsCollecting(bool state)
    {
        isCollecting = state;

        ServicePluginHandler &servicePluginHandler = ServicePluginHandler::GetInstance();
        void* handle = servicePluginHandler.GetSoHandler(ServicePluginHandler::ServicePluginType::PERF_GENIUS_PLUGIN);
        if (!handle) {
            WLOGE("Get service plugin handler failed.");
            return;
        }

        reportFunc_ = reinterpret_cast<ReportDataFunc>(dlsym(handle, "PerfCmdHandle"));
        if (!reportFunc_) {
            WLOGE("PerfCmdHandle Error loading symbol");
            return;
        }

        std::vector<int32_t> resId = {4206};
        std::vector<int64_t> endTime = {0};
        std::vector<int64_t> value = {110};
        if (!state) {
            value = {100};
        }

        int ret = reportFunc_(resId, value, endTime, "");
        if (ret < 0) {
            WLOGE("reportFunc_ failed, ret: %d", ret);
        }
    }
}
}
