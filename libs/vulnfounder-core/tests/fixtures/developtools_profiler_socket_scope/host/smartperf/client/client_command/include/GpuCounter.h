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

#ifndef GPU_COUNTER_H
#define GPU_COUNTER_H

#include "string"
#include "vector"
#include "sp_profiler.h"
#include "../interface/GpuCounterCallback.h"
#include "thread"
#include "mutex"

namespace OHOS {
    namespace SmartPerf {
        class GpuCounter : public SpProfiler {
        public:
            enum GcStatus {
                GC_INIT = 0,
                GC_RUNNING,
            };

            enum GcCollectType {
                GC_START = 0,
                GC_RESTART,
            };

        public:
            std::map<std::string, std::string> ItemData() override;
            void StartExecutionOnce(bool isPause) override;
            void FinishtExecutionOnce(bool isPause) override;

            static GpuCounter &GetInstance()
            {
                static GpuCounter instance;
                return instance;
            }
            void StartCollect(GcCollectType type);
            void StopCollect();
            std::vector<std::string> &GetGpuCounterData();
            std::vector<std::string> &GetGpuCounterSaveReportData();
            void AddGpuCounterRealtimeData(const std::string& dataString);
            void SetSavePathDirectory(const std::string& dir);
            void SaveData(const std::string& path);
            void SetFrequency(const int& freq);
            std::mutex &GetGpuCounterLock();
            void SetIsPause(bool isPause);
            std::map<std::string, std::string> GetGpuRealtimeData();
        private:
            GpuCounter();
            GpuCounter(const GpuCounter &);
            GpuCounter &operator = (const GpuCounter &);
            GcStatus gcStatus = GC_INIT;
            std::unique_ptr<std::vector<std::string>> gpuCounterData;
            std::unique_ptr<std::vector<std::string>> gpuCounterSaveReportData;
            std::mutex realtimeDataLock;
            std::mutex gpuCounterLock;
            std::string gpuCounterRealtimeData;
            const std::string createPlugin = "onCreatePlugin";
            std::string savePathDirectory_ {"/data/local/tmp/"};
            int frequency = 50;
            bool isPause_ {false};
        };
    };
}


#endif
