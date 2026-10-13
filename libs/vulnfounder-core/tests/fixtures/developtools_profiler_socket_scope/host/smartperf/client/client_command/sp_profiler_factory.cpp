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
#include <iostream>
#include "include/AI_schedule.h"
#include "include/CPU.h"
#include "include/DDR.h"
#include "include/GameEvent.h"
#include "include/GetLog.h"
#include "include/GPU.h"
#include "include/FPS.h"
#include "include/RAM.h"
#include "include/Network.h"
#include "include/Power.h"
#include "include/Temperature.h"
#include "include/ByTrace.h"
#include "include/sp_utils.h"
#include "include/sp_profiler_factory.h"
#include "include/Capture.h"
#include "include/navigation.h"
#include "include/sp_log.h"
#include "include/FileDescriptor.h"
#include "include/Threads.h"
#include "include/GpuCounter.h"
#include "effective.h"
#include "include/cpu_info.h"
#include "include/lock_frequency.h"
#include "include/hiperf.h"
#include "include/sdk_data_recv.h"
#include "include/jitters.h"
#include "include/shader.h"
#include "include/VisualEffectDisPatch.h"

namespace OHOS {
namespace SmartPerf {
SpProfiler *SpProfilerFactory::GetProfilerItem(MessageType messageType)
{
    SpProfiler* profiler = nullptr;
    switch (messageType) {
        case MessageType::GET_CPU_FREQ_LOAD:
            profiler = &CPU::GetInstance();
            break;
        case MessageType::GET_FPS_AND_JITTERS:
        case MessageType::GET_CUR_FPS:
            profiler = &FPS::GetInstance();
            break;
        case MessageType::GET_GPU_FREQ:
        case MessageType::GET_GPU_LOAD:
            profiler = &GPU::GetInstance();
            break;
        case MessageType::GET_DDR_FREQ:
            profiler = &DDR::GetInstance();
            break;
        case MessageType::GET_RAM_INFO:
            profiler = &RAM::GetInstance();
            break;
        case MessageType::GET_LOG:
            profiler = &GetLog::GetInstance();
            break;
        case MessageType::GET_PROCESS_THREADS:
            profiler = &Threads::GetInstance();
            break;
        case MessageType::GET_PROCESS_FDS:
            profiler = &FileDescriptor::GetInstance();
            break;
        default:
            break;
    }
    if (profiler == nullptr) {
        profiler = GetProfilerItemContinue(messageType);
    }
    return profiler;
}
SpProfiler *SpProfilerFactory::GetProfilerItemContinue(MessageType messageType)
{
    SpProfiler* profiler = nullptr;
    switch (messageType) {
        case MessageType::GET_TEMPERATURE:
            profiler = &Temperature::GetInstance();
            break;
        case MessageType::GET_POWER:
            profiler = &Power::GetInstance();
            break;
        case MessageType::GET_CAPTURE:
            Capture::GetInstance().SocketMessage();
            profiler = &Capture::GetInstance();
            break;
        case MessageType::CATCH_NETWORK_TRAFFIC:
        case MessageType::GET_NETWORK_TRAFFIC:
            profiler = &Network::GetInstance();
            break;
        default:
            break;
    }
    return profiler;
}

void SpProfilerFactory::SetProfilerPkg(const std::string &pkg)
{
    LOGD("SpProfilerFactory setPKG:%s", pkg.c_str());
    FPS::GetInstance().SetPackageName(pkg);
    Jitters::GetInstance().SetPackageName(pkg);
    RAM::GetInstance().SetPackageName(pkg);
    CPU::GetInstance().SetPackageName(pkg);
    Threads::GetInstance().SetPackageName(pkg);
    FileDescriptor::GetInstance().SetPackageName(pkg);
}

void SpProfilerFactory::SetProfilerPidByPkg(std::string &pid, std::string pids)
{
    LOGD("SpProfilerFactory setPID:%s", pid.c_str());
    FPS::GetInstance().SetProcessId(pid);
    Jitters::GetInstance().SetProcessId(pid);
    Hiperf::GetInstance().SetProcessId(pid);
    RAM::GetInstance().SetProcessId(pids.empty() ? pid : pids);
    CPU::GetInstance().SetProcessId(pids.empty() ? pid : pids);
    Navigation::GetInstance().SetProcessId(pid);
    AISchedule::GetInstance().SetProcessId(pid);
    Threads::GetInstance().SetProcessId(pids.empty() ? pid : pids);
    FileDescriptor::GetInstance().SetProcessId(pids.empty() ? pid : pids);
    CPUInfo::GetInstance().SetPids(pids.empty() ? pid : pids);
}

SpProfiler *SpProfilerFactory::GetCmdProfilerItem(CommandType commandType, bool cmdFlag)
{
    SpProfiler *profiler = nullptr;
    std::string winId = "";
    switch (commandType) {
        case CommandType::CT_C:
            if (cmdFlag) {
                profiler = &CPU::GetInstance();
            }
            break;
        case CommandType::CT_G:
            profiler = &GPU::GetInstance();
            break;
        case CommandType::CT_F:
            winId = SPUtils::GetWinId();
            SPUtils::EnDumpFun(winId);
            FPS::GetInstance().SetWinId(winId);
            if (cmdFlag) {
                profiler = &FPS::GetInstance();
            }
            break;
        case CommandType::CT_D:
            profiler = &DDR::GetInstance();
            break;
        case CommandType::CT_P:
            profiler = &Power::GetInstance();
            break;
        case CommandType::CT_T:
            profiler = &Temperature::GetInstance();
            break;
        case CommandType::CT_R:
            if (cmdFlag) {
                profiler = &RAM::GetInstance();
            }
            break;
        default:
            break;
    }
    if (profiler == nullptr) {
        profiler = GetCmdProfilerItemOption(commandType, cmdFlag);
    }
    return profiler;
}

SpProfiler *SpProfilerFactory::GetCmdProfilerItemOption(CommandType commandType, bool cmdFlag)
{
    SpProfiler *profiler = nullptr;
    switch (commandType) {
        case CommandType::CT_NET:
            profiler = &Network::GetInstance();
            break;
        case CommandType::CT_NAV:
            profiler = &Navigation::GetInstance();
            break;
        case CommandType::CT_TRACE:
            ByTrace::GetInstance().SetByTrace();
            FPS::GetInstance().SetTraceCatch();
            profiler = &ByTrace::GetInstance();
            break;
        case CommandType::CT_AS:
            profiler = &AISchedule::GetInstance();
            break;
        case CommandType::CT_JITTERS:
            profiler = &Jitters::GetInstance();
            break;
        case CommandType::CT_SH:
            profiler = &Shader::GetInstance();
            break;
        case CommandType::CT_VED: {
            profiler = &VisualEffectDisPatch::GetInstance();
            break;
        }
        default:
            break;
    }
    if (profiler == nullptr) {
        profiler = GetCmdProfilerItemContinue(commandType, cmdFlag);
    }
    return profiler;
}

SpProfiler *SpProfilerFactory::GetCmdProfilerItemContinue(CommandType commandType, bool cmdFlag)
{
    SpProfiler *profiler = nullptr;
    switch (commandType) {
        case CommandType::CT_SNAPSHOT:
            if (cmdFlag) {
                profiler = &Capture::GetInstance();
            }
            break;
        case CommandType::CT_THREADS:
            profiler = &Threads::GetInstance().GetInstance();
            break;
        case CommandType::CT_FDS:
            if (cmdFlag) {
                profiler = &FileDescriptor::GetInstance().GetInstance();
            }
            break;
        case CommandType::CT_GE:
            profiler = &GameEvent::GetInstance();
            break;
        case CommandType::CT_GC: {
            profiler = &GpuCounter::GetInstance();
            break;
        }
        case CommandType::CT_O: {
            profiler = &SdkDataRecv::GetInstance();
            break;
        }
        case CommandType::CT_FL:
        case CommandType::CT_FTL: {
            profiler = &Effective::GetInstance();
            break;
        }
        case CommandType::CT_CI: {
            profiler = &CPUInfo::GetInstance();
            break;
        }
        case CommandType::CT_LF: {
            profiler = &LockFrequency::GetInstance();
            break;
        }
        case CommandType::CT_HCI: {
            profiler = &Hiperf::GetInstance();
            break;
        }
        default:
            break;
    }
    return profiler;
}
}
}
