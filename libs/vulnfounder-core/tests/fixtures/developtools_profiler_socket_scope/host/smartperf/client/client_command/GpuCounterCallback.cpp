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

#include <string>
#include <sstream>
#include "include/sp_log.h"
#include "include/sp_utils.h"
#include "include/GpuCounter.h"
#include "interface/GpuCounterCallback.h"

namespace OHOS {
    namespace SmartPerf {
        GpuCounterCallbackImpl::GpuCounterCallbackImpl()
        {
            GpuPerfInfo firstData;
            firstData.startTime = SPUtils::GetCurTime();
            firstData.duration = 0;
            firstData.gpuActive = 0;
            firstData.drawCalls = 0;
            firstData.primitives = 0;
            firstData.vertexCounts = 0;
            firstData.totalInstruments = 0;
            firstData.gpuLoadPercentage = 0;
            firstData.vertexLoadPercentage = 0;
            firstData.fragmentLoadPercentage = 0;
            firstData.computeLoadPercentage = 0;
            firstData.textureLoadPercentage = 0;
            firstData.memoryReadBandwidth = 0;
            firstData.memoryWriteBandwidth = 0;
            firstData.memoryBandwidthPercentage = 0;
            firstData.remainTime = maxTime;
            realtimeGpuPerfInfoData = firstData;
            gpuCounter.push_back(firstData);
        }


        unsigned long long GpuCounterCallbackImpl::JoinSocketDataPercentFunction(uint32_t itemFirst,
            int32_t durationFirst, uint32_t itemSecond, int32_t durationSecond) const
        {
            return (static_cast<unsigned long long>(itemFirst) * static_cast<unsigned long long>(durationFirst) +
                static_cast<unsigned long long>(itemSecond) * static_cast<unsigned long long>(durationSecond)) /
                (static_cast<unsigned long long>(durationFirst) + static_cast<unsigned long long>(durationSecond));
        }

        void GpuCounterCallbackImpl::JoinSocketDataValue(GpuPerfInfo *newData)
        {
            realtimeGpuPerfInfoData.gpuActive += newData->gpuActive;
            realtimeGpuPerfInfoData.drawCalls += newData->drawCalls;
            realtimeGpuPerfInfoData.primitives += newData->primitives;
            realtimeGpuPerfInfoData.vertexCounts += newData->vertexCounts;
            realtimeGpuPerfInfoData.totalInstruments += newData->totalInstruments;
            realtimeGpuPerfInfoData.memoryReadBandwidth += newData->memoryReadBandwidth;
            realtimeGpuPerfInfoData.memoryWriteBandwidth += newData->memoryWriteBandwidth;
        }

        void GpuCounterCallbackImpl::JoinSocketDataPercent(GpuPerfInfo *newData)
        {
            realtimeGpuPerfInfoData.gpuLoadPercentage = JoinSocketDataPercentFunction(
                realtimeGpuPerfInfoData.gpuLoadPercentage, realtimeGpuPerfInfoData.duration,
                newData->gpuLoadPercentage, newData->duration);
            realtimeGpuPerfInfoData.vertexLoadPercentage = JoinSocketDataPercentFunction(
                realtimeGpuPerfInfoData.vertexLoadPercentage, realtimeGpuPerfInfoData.duration,
                newData->vertexLoadPercentage, newData->duration);
            realtimeGpuPerfInfoData.fragmentLoadPercentage = JoinSocketDataPercentFunction(
                realtimeGpuPerfInfoData.fragmentLoadPercentage, realtimeGpuPerfInfoData.duration,
                newData->fragmentLoadPercentage, newData->duration);
            realtimeGpuPerfInfoData.computeLoadPercentage = JoinSocketDataPercentFunction(
                realtimeGpuPerfInfoData.computeLoadPercentage, realtimeGpuPerfInfoData.duration,
                newData->computeLoadPercentage, newData->duration);
            realtimeGpuPerfInfoData.textureLoadPercentage = JoinSocketDataPercentFunction(
                realtimeGpuPerfInfoData.textureLoadPercentage, realtimeGpuPerfInfoData.duration,
                newData->textureLoadPercentage, newData->duration);
        }

        void GpuCounterCallbackImpl::JoinSocketData(GpuPerfInfo *newData)
        {
            JoinSocketDataValue(newData);
            JoinSocketDataPercent(newData);

            realtimeGpuPerfInfoData.duration += newData->duration;
        }

        unsigned long long GpuCounterCallbackImpl::SplitSocketDataValueFunction(uint32_t value, int32_t interval,
            int32_t duration) const
        {
            return static_cast<unsigned long long>(value) *
                static_cast<unsigned long long>(interval) /
                static_cast<unsigned long long>(duration);
        }

        void GpuCounterCallbackImpl::SplitSocketDataValue(int32_t interval)
        {
            GpuCounter &gpuCounterInstance = GpuCounter::GetInstance();

            unsigned long long gpuActiveTargetValue = SplitSocketDataValueFunction(
                realtimeGpuPerfInfoData.gpuActive, interval,
                realtimeGpuPerfInfoData.duration);
            unsigned long long drawCallsTargetValue = SplitSocketDataValueFunction(
                realtimeGpuPerfInfoData.drawCalls, interval,
                realtimeGpuPerfInfoData.duration);
            unsigned long long primitivesTargetValue = SplitSocketDataValueFunction(
                realtimeGpuPerfInfoData.primitives, interval,
                realtimeGpuPerfInfoData.duration);
            unsigned long long vertexCountsTargetValue = SplitSocketDataValueFunction(
                realtimeGpuPerfInfoData.vertexCounts, interval,
                realtimeGpuPerfInfoData.duration);
            unsigned long long totalInstrumentsTargetValue = SplitSocketDataValueFunction(
                realtimeGpuPerfInfoData.totalInstruments, interval,
                realtimeGpuPerfInfoData.duration);
            unsigned long long memoryReadBandwidthTargetValue = SplitSocketDataValueFunction(
                realtimeGpuPerfInfoData.memoryReadBandwidth, interval,
                realtimeGpuPerfInfoData.duration);
            unsigned long long memoryWriteBandwidthTargetValue = SplitSocketDataValueFunction(
                realtimeGpuPerfInfoData.memoryWriteBandwidth, interval,
                realtimeGpuPerfInfoData.duration);
                
            gpuCounterInstance.AddGpuCounterRealtimeData(std::to_string(
                realtimeGpuPerfInfoData.gpuActive - gpuActiveTargetValue) + "_");
            gpuCounterInstance.AddGpuCounterRealtimeData(std::to_string(
                realtimeGpuPerfInfoData.drawCalls - drawCallsTargetValue) + "_");
            gpuCounterInstance.AddGpuCounterRealtimeData(std::to_string(
                realtimeGpuPerfInfoData.primitives - primitivesTargetValue) + "_");
            gpuCounterInstance.AddGpuCounterRealtimeData(std::to_string(
                realtimeGpuPerfInfoData.vertexCounts - vertexCountsTargetValue) + "_");
            gpuCounterInstance.AddGpuCounterRealtimeData(std::to_string(
                realtimeGpuPerfInfoData.totalInstruments - totalInstrumentsTargetValue) + "_");
            gpuCounterInstance.AddGpuCounterRealtimeData(std::to_string(
                realtimeGpuPerfInfoData.memoryReadBandwidth - memoryReadBandwidthTargetValue) + "_");
            gpuCounterInstance.AddGpuCounterRealtimeData(std::to_string(
                realtimeGpuPerfInfoData.memoryWriteBandwidth - memoryWriteBandwidthTargetValue) + "_");

            realtimeGpuPerfInfoData.gpuActive = gpuActiveTargetValue;
            realtimeGpuPerfInfoData.drawCalls = drawCallsTargetValue;
            realtimeGpuPerfInfoData.primitives = primitivesTargetValue;
            realtimeGpuPerfInfoData.vertexCounts = vertexCountsTargetValue;
            realtimeGpuPerfInfoData.totalInstruments = totalInstrumentsTargetValue;
            realtimeGpuPerfInfoData.memoryReadBandwidth = memoryReadBandwidthTargetValue;
            realtimeGpuPerfInfoData.memoryWriteBandwidth = memoryWriteBandwidthTargetValue;
        }

        void GpuCounterCallbackImpl::SplitSocketDataPercent()
        {
            GpuCounter &gpuCounterInstance = GpuCounter::GetInstance();

            gpuCounterInstance.AddGpuCounterRealtimeData(
                std::to_string(realtimeGpuPerfInfoData.gpuLoadPercentage) + "_");
            gpuCounterInstance.AddGpuCounterRealtimeData(
                std::to_string(realtimeGpuPerfInfoData.vertexLoadPercentage) + "_");
            gpuCounterInstance.AddGpuCounterRealtimeData(
                std::to_string(realtimeGpuPerfInfoData.fragmentLoadPercentage) + "_");
            gpuCounterInstance.AddGpuCounterRealtimeData(
                std::to_string(realtimeGpuPerfInfoData.computeLoadPercentage) + "_");
            gpuCounterInstance.AddGpuCounterRealtimeData(
                std::to_string(realtimeGpuPerfInfoData.textureLoadPercentage) + ";");
        }

        void GpuCounterCallbackImpl::SplitSocketData()
        {
            int32_t interval = realtimeGpuPerfInfoData.duration - maxDuration;
            SplitSocketDataValue(interval);
            SplitSocketDataPercent();
            realtimeGpuPerfInfoData.duration = interval;
        }

        void GpuCounterCallbackImpl::GetRealTime(GpuPerfInfo *newData)
        {
            if (newData == nullptr) {
                WLOGE("GetRealTime newData is nullptr");
                return;
            }

            JoinSocketData(newData);
            if ((realtimeGpuPerfInfoData.duration == 0) || (newData->duration == 0)) {
                WLOGE("Invalid duration found: realtime = %d, newData = %d",
                    realtimeGpuPerfInfoData.duration, newData->duration);
                return;
            }
            while (realtimeGpuPerfInfoData.duration >= maxDuration) {
                SplitSocketData();
            }
        }

        std::string GpuCounterCallbackImpl::GetGpuPerfInfoItem(const GpuPerfInfo *itemData) const
        {
            std::ostringstream oss;
            if (itemData == nullptr) {
                WLOGE("GpuCounter get itemData is nullptr");
                return "";
            }
            oss << itemData->startTime << ","
                << itemData->duration << ","
                << itemData->gpuActive << ","
                << itemData->drawCalls << ","
                << itemData->primitives << ","
                << itemData->vertexCounts << ","
                << itemData->totalInstruments << ","
                << itemData->gpuLoadPercentage << ","
                << itemData->vertexLoadPercentage << ","
                << itemData->fragmentLoadPercentage << ","
                << itemData->computeLoadPercentage << ","
                << itemData->textureLoadPercentage << ","
                << itemData->memoryReadBandwidth << ","
                << itemData->memoryWriteBandwidth << ","
                << itemData->memoryBandwidthPercentage << ",";
            return oss.str();
        }

        int GpuCounterCallbackImpl::OnGpuData(std::vector<GpuPerfInfo> &gpuPerfInfos)
        {
            if (gpuPerfInfos.empty()) {
                WLOGE("Receive gpuPerfInfos is empty!");
                return -1;
            }

            GpuCounter &gpuCounterInstance = GpuCounter::GetInstance();

            for (const auto& gpuPerfInfo : gpuPerfInfos) {
                unsigned int gpuCounterBackSize = gpuCounter.size();
                gpuCounter.push_back(gpuPerfInfo);
                unsigned int gpuCounterSize = gpuCounter.size();
                if (gpuCounterSize <= gpuCounterBackSize) {
                    WLOGE("gpuCounter data len error!");
                    return -1;
                }
                GpuPerfInfo *newData = &gpuCounter[gpuCounterSize - 1];
                GpuPerfInfo *backData = &gpuCounter[gpuCounterSize - 2];
                if (newData == nullptr || backData == nullptr) {
                    WLOGE("gpuCounter data pointer is null!");
                    return -1;
                }
                long long durationTime = newData->startTime - backData->startTime;

                // 如果两次数据间隔过短，则舍弃新数据
                if (durationTime < collectInterval) {
                    WLOGE("Start time(%lld, %lld) make duration time(%lld) too short",
                        newData->startTime, backData->startTime, durationTime);
                    gpuCounter.pop_back();
                    continue;
                }
                backData->duration = durationTime;
                std::string gpuPerfInfoItemStr = GetGpuPerfInfoItem(backData);
                gpuCounterInstance.GetGpuCounterData().push_back(gpuPerfInfoItemStr);
                gpuCounterInstance.GetGpuCounterSaveReportData().push_back(gpuPerfInfoItemStr);
                GetRealTime(backData);
            }

            if (gpuPerfInfos[0].remainTime <= restartTime) {
                gpuCounterInstance.StartCollect(GpuCounter::GC_RESTART);
            }
            return 0;
        }
    }
}