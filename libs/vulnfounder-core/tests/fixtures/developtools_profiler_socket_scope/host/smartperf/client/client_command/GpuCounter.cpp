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

#include "chrono"
#include "string"
#include "thread"
#include "fstream"
#include <iostream>
#include <dlfcn.h>
#include "include/sp_log.h"
#include "include/GpuCounter.h"
#include "include/service_plugin.h"
#include "interface/GpuCounterCallback.h"
#include "interface/GameServicePlugin.h"

namespace OHOS {
    namespace SmartPerf {
        GpuCounter::GpuCounter()
            : gpuCounterData(std::make_unique<std::vector<std::string>>()),
              gpuCounterSaveReportData(std::make_unique<std::vector<std::string>>()) {}

        std::map<std::string, std::string> GpuCounter::ItemData()
        {
            std::map<std::string, std::string> gpuCounterDataMap;
            LOGI("GpuCounter:ItemData map size(%u)", gpuCounterDataMap.size());
            return gpuCounterDataMap;
        }

        void GpuCounter::StartExecutionOnce(bool isPause)
        {
            StartCollect(GpuCounter::GC_START);
        }

        void GpuCounter::FinishtExecutionOnce(bool isPause)
        {
            std::unique_lock<std::mutex> lock(gpuCounterLock);
            SaveData(savePathDirectory_);
            StopCollect();
            if (!isPause_) {
                gpuCounterData->clear();
            }
        }

        void GpuCounter::SetSavePathDirectory(const std::string& dir)
        {
            savePathDirectory_ = dir;
        }

        void GpuCounter::StartCollect(GcCollectType type)
        {
            if (frequency == 0) {
                WLOGE("GpuCounter frequency is not set");
                return;
            }
            std::unique_ptr<GpuCounterCallback> gpuCounterCallback = std::make_unique<GpuCounterCallbackImpl>();

            // 1s 一次Gameservice回调
            const int duration = 1000;

            ServicePluginHandler &servicePluginHandler = ServicePluginHandler::GetInstance();
            void* handle = servicePluginHandler.GetSoHandler(ServicePluginHandler::ServicePluginType::GAME_PLUGIN);
            if (!handle) {
                WLOGE("Get service plugin handler failed.");
                return;
            }

            typedef GameServicePlugin *(*GetServicePlugin)();
            GetServicePlugin servicePlugin = (GetServicePlugin)dlsym(handle, createPlugin.c_str());
            if (!servicePlugin) {
                WLOGE("GameServicePlugin Error loading symbol");
                return;
            }

            if (type == GC_START && gcStatus == GC_INIT) {
                if (!isPause_) {
                    gpuCounterData->clear();
                    gpuCounterRealtimeData.clear();
                }
                int ret = servicePlugin()->StartGetGpuPerfInfo(duration, frequency, std::move(gpuCounterCallback));
                if (ret == 0) {
                    gcStatus = GC_RUNNING;
                } else {
                    WLOGE("GpuCounter call gameService error, ret = %d", ret);
                }
            } else if (type == GC_RESTART && gcStatus == GC_RUNNING) {
                int ret = servicePlugin()->StartGetGpuPerfInfo(duration, frequency, std::move(gpuCounterCallback));
                if (ret != 0) {
                    WLOGE("GpuCounter call gameService error, ret = %d", ret);
                }
            } else {
                WLOGE("GpuCounter state error, type: %d, state: %d", type, gcStatus);
            }
        }

        void GpuCounter::SaveData(const std::string& path)
        {
            // device与editor采集都会走tcp stop时的SaveData，但是deivce同时会走FinishtExecutionOnce导致SaveData执行两次
            // 目前device在第一次保存数据后会清空，第二次SaveData实际不生效
            if (gcStatus != GC_RUNNING || gpuCounterData->size() <= 0 || path.empty()) {
                return;
            }
            savePathDirectory_ = path;
            char gpuCounterDataDirChar[PATH_MAX] = {0x00};
            if (realpath(path.c_str(), gpuCounterDataDirChar) == nullptr) {
                WLOGE("data dir %s is nullptr", path.c_str());
                return;
            }
            std::string gpuCounterDataPath = std::string(gpuCounterDataDirChar) + "/gpu_counter.csv";
            std::ofstream outFile;
            outFile.open(gpuCounterDataPath.c_str(), std::ios::out | std::ios::trunc);
            if (!outFile.is_open()) {
                WLOGE("open GpuCounter data file failed. %s", gpuCounterDataPath.c_str());
                return;
            }
            static const std::string title = "startTime,"
                "duration,"
                "gpuActive,"
                "drawCalls,"
                "primitives,"
                "vertexCounts,"
                "totalInstruments,"
                "gpuLoadPercentage,"
                "vertexLoadPercentage,"
                "fragmentLoadPercentage,"
                "computeLoadPercentage,"
                "textureLoadPercentage,"
                "memoryReadBandwidth,"
                "memoryWriteBandwidth,"
                "memoryBandwidthPercentage\r";
            outFile << title << std::endl;
            std::unique_lock<std::mutex> lock(realtimeDataLock);
            for (const auto& data : *gpuCounterSaveReportData) {
                outFile << data << std::endl;
            }
            outFile.close();
        }

        std::vector<std::string> &GpuCounter::GetGpuCounterData()
        {
            return *gpuCounterData;
        }

        std::vector<std::string> &GpuCounter::GetGpuCounterSaveReportData()
        {
            return *gpuCounterSaveReportData;
        }

        std::map<std::string, std::string> GpuCounter::GetGpuRealtimeData()
        {
            std::unique_lock<std::mutex> lock(realtimeDataLock);
            std::map<std::string, std::string> gpuCounterDataMap = {};
            if (!gpuCounterRealtimeData.empty()) {
                gpuCounterDataMap.insert({"gpuCounterData", gpuCounterRealtimeData});
                gpuCounterRealtimeData.clear();
            }
            return gpuCounterDataMap;
        }
        void GpuCounter::AddGpuCounterRealtimeData(const std::string& dataString)
        {
            std::unique_lock<std::mutex> lock(realtimeDataLock);
            gpuCounterRealtimeData += dataString;
        }

        void GpuCounter::StopCollect()
        {
            if (gcStatus != GC_RUNNING) {
                return;
            }
            ServicePluginHandler &servicePluginHandler = ServicePluginHandler::GetInstance();
            void* handle = servicePluginHandler.GetSoHandler(ServicePluginHandler::ServicePluginType::GAME_PLUGIN);
            if (!handle) {
                WLOGE("Get service plugin handler failed.");
                return;
            }

            typedef GameServicePlugin *(*GetServicePlugin)();
            GetServicePlugin servicePlugin = (GetServicePlugin)dlsym(handle, createPlugin.c_str());
            if (!servicePlugin) {
                WLOGE("GameServicePlugin Error loading symbol");
                return;
            }

            int ret = servicePlugin()->StopGetGpuPerfInfo();
            if (ret == 0) {
                gcStatus = GC_INIT;
            }
        }

        void GpuCounter::SetFrequency(const int& freq)
        {
            frequency = freq;
        }

        std::mutex &GpuCounter::GetGpuCounterLock()
        {
            return gpuCounterLock;
        }

        void GpuCounter::SetIsPause(bool isPause)
        {
            isPause_ = isPause;
        }
    }
}