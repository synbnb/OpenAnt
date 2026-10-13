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

#ifndef GPU_COUNTER_CALLBACK_H
#define GPU_COUNTER_CALLBACK_H
#include "vector"

namespace OHOS {
    namespace SmartPerf {
        struct GpuPerfInfo {
            int64_t remainTime = 0;
            int64_t startTime = 0;
            int32_t duration = 0;
            uint32_t gpuActive = 0;
            uint32_t drawCalls = 0;
            uint64_t primitives = 0;
            uint64_t vertexCounts = 0;
            uint64_t totalInstruments = 0;
            uint32_t gpuLoadPercentage = 0;
            uint32_t vertexLoadPercentage = 0;
            uint32_t fragmentLoadPercentage = 0;
            uint32_t computeLoadPercentage = 0;
            uint32_t textureLoadPercentage = 0;
            uint32_t memoryReadBandwidth = 0;
            uint32_t memoryWriteBandwidth = 0;
            uint32_t memoryBandwidthPercentage = 0;
        };

        class GpuCounterCallback {
        public:
            GpuCounterCallback() = default;
            virtual ~GpuCounterCallback() = default;
            virtual int OnGpuData(std::vector<GpuPerfInfo> &gpuPerfInfos) = 0;
        };

        class GpuCounterCallbackImpl  : public GpuCounterCallback {
        public:
            GpuCounterCallbackImpl();
            int OnGpuData(std::vector<GpuPerfInfo> &gpuPerfInfos) override;

        private:
            void GetRealTime(GpuPerfInfo *newData);
            void JoinSocketDataValue(GpuPerfInfo *newData);
            unsigned long long JoinSocketDataPercentFunction(uint32_t itemFirst, int32_t durationFirst,
                uint32_t itemSecond, int32_t durationSecond) const;
            void JoinSocketDataPercent(GpuPerfInfo *newData);
            void JoinSocketData(GpuPerfInfo *newData);
            unsigned long long SplitSocketDataValueFunction(uint32_t value, int32_t interval, int32_t duration) const;
            void SplitSocketDataValue(int32_t interval);
            void SplitSocketDataPercent();
            void SplitSocketData();
            std::string GetGpuPerfInfoItem(const GpuPerfInfo *itemData) const;
            std::vector<GpuPerfInfo> gpuCounter;
            const long long collectInterval = 50;
            const int64_t maxTime = 10800000;
            const int64_t restartTime = 300000;
            const int32_t maxDuration = 1000;
            GpuPerfInfo realtimeGpuPerfInfoData;
        };
    }
}

#endif
