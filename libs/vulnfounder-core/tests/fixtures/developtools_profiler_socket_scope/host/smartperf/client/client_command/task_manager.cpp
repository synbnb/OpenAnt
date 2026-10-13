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

#include "task_manager.h"
#include "common.h"
#include <chrono>
#include <sys/types.h>
#include <unistd.h>
#include "securec.h"

#include "include/heartbeat.h"
#include "include/sp_utils.h"
#include "include/sp_csv_util.h"
#include "include/sp_profiler_factory.h"
#include "include/sp_thread_socket.h"
#include "include/startup_delay.h"
#include "include/ByTrace.h"
#include "include/smartperf_command.h"
#include "include/sp_log.h"
#include "include/RAM.h"
#include "include/common.h"
#include "include/FPS.h"
#include "include/sp_task.h"
#include "include/CPU.h"
#include "include/navigation.h"
#include "include/AI_schedule.h"
#include "include/Threads.h"
#include "include/FileDescriptor.h"
#include "include/GpuCounter.h"
#include "include/hiperf.h"
#include "Capture.h"
#include <sys/syscall.h>
#include <filesystem>
#include "include/sdk_data_recv.h"
#include "include/jitters.h"
#include "include/shader.h"

namespace {
OHOS::SmartPerf::TaskManager* g_mgr = nullptr;
thread_local OHOS::SmartPerf::ThreadLocal g_datas;
constexpr int32_t SAVE_DATA_INTERVAL_MINUTE = 5;
constexpr int32_t THE_MINUTE = 60;
}

namespace OHOS::SmartPerf {
ThreadLocal::ThreadLocal()
{
    if (g_mgr == nullptr) {
        return;
    }
    g_mgr->RegisterThreadLocal(this);
}

ThreadLocal::~ThreadLocal()
{
    if (g_mgr == nullptr || (datasA_.empty() && datasB_.empty())) {
        return;
    }
    g_mgr->CollectData(datasA_);
    g_mgr->CollectData(datasB_);
}

TaskManager::TaskManager(bool isIPC)
{
    g_mgr = this;
    if (isIPC) {
        Capture::GetInstance().SocketMessage();
    }
}

void TaskManager::GpuCounterProcess(const ArgumentParser::ArgValue& value)
{
    const int defaultFreq = 50;
    const int minFreq = 50;
    const int maxFreq = 1000;
    if (std::holds_alternative<bool>(value)) {
        // 如果val是bool类型，代表参数为-gc，使用默认频率
        GpuCounter::GetInstance().SetFrequency(defaultFreq);
        return;
    }

    // -GPU_COUNTER为int类型
    // 参数拓展时，如果有其他类型，需要增加if判断，否则会variant识别异常导致crash
    int frequency = std::get<int>(value);
    // GPU_COUNTER频率最大支持10000，但daemon采集间隔是1000。频率设置应小于采集间隔。
    if (frequency <= maxFreq && frequency >= minFreq && frequency % minFreq == 0) {
        GpuCounter::GetInstance().SetFrequency(frequency);
    } else {
        LOGW("GPU_COUNTER frequency must be a factor of 50 and in range [50,1000], " +
             "this frequency is %d, set to 50", frequency);
        GpuCounter::GetInstance().SetFrequency(defaultFreq);
    }
}

void TaskManager::SpecialKeyProcess(const std::string specKey)
{
    if (specKey == "-LOW_POWER") {
        FPS::GetInstance().hapLowFpsFlag = true;
    }
    if (specKey == "-fc") {
        FPS::GetInstance().hapNeedCatonInfo = true;
    }
}

void TaskManager::AddTask(const std::unordered_map<std::string, ArgumentParser::ArgValue>& argv)
{
    for (auto& [key, val] : argv) {
        auto iter = COMMAND_MAP.find(key);
        if (iter == COMMAND_MAP.end()) {
            iter = COMMAND_SHELL_MAP.find(key);
        }
        if (iter == COMMAND_MAP.end() || iter == COMMAND_SHELL_MAP.end()) {
            continue;
        }
        SpecialKeyProcess(key);
        HandleCommandType(iter->second, val);

        SpProfiler* pro = SpProfilerFactory::GetCmdProfilerItem(iter->second, true);
        if (pro == nullptr) {
            continue;
        }
        pro->ipcCallback_ = ipcCallback_;
        if (iter->second == CommandType::CT_C || iter->second == CommandType::CT_P) {
            priorityTask_.insert(pro);
        } else {
            normalTask_.insert(pro);
        }
    }
}

void TaskManager::HandleCommandType(CommandType cmdType, const ArgumentParser::ArgValue& val)
{
    switch (cmdType) {
        case CommandType::CT_N: {
            collectCount_ = std::get<int>(val);
            break;
        }
        case CommandType::CT_PKG:
        case CommandType::CT_PID: {
            GetProcessInfo(cmdType, val);
            break;
        }
        case CommandType::CT_PRINT: {
            printDataInfo_ = true;
            break;
        }
        case CommandType::CT_VIEW: {
            FPS::GetInstance().SetLayerName(std::get<std::string>(val));
            break;
        }
        case CommandType::CT_OUT: {
            SetFilePath(std::get<std::string>(val));
            break;
        }
        case CommandType::CT_GC: {
            GpuCounterProcess(val);
            break;
        }
        default:
            break;
    }
}

void TaskManager::AddTask(const std::string& argv)
{
    LOGD("AddTask argv (%s)", argv.c_str());
    parameter_.Parse(argv);
    AddTask(parameter_.Values());
}

void TaskManager::AddTask(SpProfiler* task, bool priority)
{
    if (task == nullptr) {
        return;
    }
    LOGD("Start the collection in the start/stop mode");
    priority ? priorityTask_.insert(task) : normalTask_.insert(task);
}

void TaskManager::AddTask(std::vector<std::string>& argv)
{
    std::string argvStr;
    for (auto& item : argv) {
        argvStr += item + " ";
    }
    AddTask(argvStr);
}

void TaskManager::SetFilePath(const std::string& fileName, bool removeCurrentFile)
{
    fileName_ = fileName;
    saveFlag_ = true;
    if (removeCurrentFile) {
        std::remove(fileName_.c_str());
    }
    std::filesystem::path fullPath = fileName;
    std::string dir = fullPath.parent_path().string();
    GpuCounter::GetInstance().SetSavePathDirectory(dir);
    SdkDataRecv::GetInstance().SetFilePath(dir);
}

std::map<std::string, std::string> TaskManager::TaskFun(SpProfiler* pro, uint32_t batch, bool record)
{
    auto mapRes = pro->ItemData();
    if (record) {
        if (g_datas.switch_) {
            g_datas.datasA_[batch].insert(mapRes.begin(), mapRes.end());
        } else {
            g_datas.datasB_[batch].insert(mapRes.begin(), mapRes.end());
        }
    }
    return mapRes;
}

void TaskManager::CollectThreadsData()
{
    for (auto& item : threadLocals_) {
        if (item == nullptr) {
            continue;
        }

        std::map<uint32_t, std::map<std::string, std::string>>& datas =
            (running_ ^ item->switch_) ? item->datasA_ : item->datasB_;

        CollectData(datas);
        std::map<uint32_t, std::map<std::string, std::string>>().swap(datas);
    }
}

void TaskManager::StartSaveFileThread()
{
    if (scheduleSaveDataTh_.joinable()) {
        LOGD("The thread save data is working");
        return;
    }
    scheduleSaveDataTh_ = std::thread([this]() {
        LOGD("running: %d, recordData: %d", running_.load(), recordData_.load());
        while (running_ && recordData_) {
            std::unique_lock<std::mutex> lock(scheduleSaveDataMtx_);
            scheduleSaveDataCond_.wait(lock);
            CollectThreadsData();
            WriteToCSV();
            std::map<uint32_t, std::map<std::string, std::string>>().swap(datas_);
            savingFile_ = false;
        }
        LOGD("The data saving thread exits");
    });
}

void TaskManager::SaveRegularly(int32_t dataIndex)
{
    if (!recordData_) {
        return;
    }

    if (dataIndex > 0 && (dataIndex % (SAVE_DATA_INTERVAL_MINUTE * THE_MINUTE) == 0) &&
        !(SpProfilerFactory::editorFlag)) {
        std::unique_lock<std::mutex> lock(mtx_);
        if (savingFile_) {
            LOGD("Saving file");
            return;
        }
        savingFile_ = true;
        for (auto& item : threadLocals_) {
            if (item == nullptr) {
                continue;
            }
            item->switch_ = !item->switch_;
        }
        LOGD("Start saving data automatically");
        scheduleSaveDataCond_.notify_all();
    }
}

void TaskManager::Start(bool record)
{
    if (priorityTask_.empty() && normalTask_.empty()) {
        return;
    }
    ProcessOnceTask(true);
    running_ = true;
    if (record) {
        saveFlag_ = true;
        SetRecordState(true);
    }
    mainLoop_ = std::thread([this]() {
        MainLoop();
    });
}

void TaskManager::Pause()
{
    std::unique_lock<std::mutex> lock(pauseMutex_);
    paused_ = true;
    LOGD("TaskManager Pause");
}

void TaskManager::Resume()
{
    {
        std::unique_lock<std::mutex> lock(pauseMutex_);
        paused_ = false;
        collectTimes_ = 0;
    }
    pauseCond_.notify_all();
    LOGD("TaskManager Resume");
}

bool TaskManager::ThreadLock()
{
    std::unique_lock<std::mutex> lock(pauseMutex_);
    pauseCond_.wait(lock, [this] {
        return !paused_ || !running_;
    });
    if (!running_) {
        return false;
    }
    return true;
}

void TaskManager::MainLoop()
{
    while (running_) {
        if (!ThreadLock()) {
            break;
        }
        long long loopStart = SPUtils::GetCurTime();
        if (dataIndex_ == 0 || collectTimes_ == 0) {
            baseTime_ = loopStart;
        }
        collectTimes_++;
        bool recordData = recordData_.load();
        if (dataIndex_++ == collectCount_) {
            break;
        }
        LOGD("data index: %u", dataIndex_);
        std::map<std::string, std::string> currDatas;
        currDatas.emplace("timestamp", std::to_string(SPUtils::GetCurTime()));
        if (recordData) {
            datas_.emplace(dataIndex_,
                std::map<std::string, std::string>{{"timestamp", std::to_string(SPUtils::GetCurTime())}});
        }
        for (auto& item : priorityTask_) {
            currDatas.merge(threadPool_.PushTask(&TaskManager::TaskFun, this, item, dataIndex_, recordData).get());
        }
        std::vector<std::future<std::map<std::string, std::string>>> result;
        for (auto& item : normalTask_) {
            result.emplace_back(threadPool_.PushTask(&TaskManager::TaskFun, this, item, dataIndex_, recordData));
        }
        for (auto& item : result) {
            currDatas.merge(item.get());
        }
        for (auto& item : OHOS::SmartPerf::GpuCounter::GetInstance().GetGpuRealtimeData()) {
            currDatas.insert(item);
        }
        if (nextTime_ != nullptr) {
            *nextTime_ = SPUtils::GetCurTime();
        }
        ProcessCurrentBatch(currDatas);
        SaveRegularly(dataIndex_);
        long long loopEnd = SPUtils::GetCurTime();
        long long sleepTime = collectTimes_ * 1000 + baseTime_ - loopEnd;
        if (sleepTime > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
        }
    }
    ProcessOnceTask(false);
    running_ = false;
    finishCond_.notify_all();
    scheduleSaveDataCond_.notify_all();
}

void TaskManager::WriteToCSV()
{
    std::unique_lock<std::mutex> lock(mtx_);
    if (datas_.empty() || !saveFlag_) {
        LOGD("datas is empty or saveFlag: %d", saveFlag_);
        return;
    }
    if (!dataFile_.is_open()) {
        char filePath[PATH_MAX] = {0};
        if (realpath(fileName_.c_str(), filePath) == nullptr) {
            if (strncpy_s(filePath, PATH_MAX, fileName_.c_str(), fileName_.size()) != 0) {
                LOGE("strncpy_s failed");
                return;
            }
            LOGE("The file %s does not exist, will create", fileName_.c_str());
        }
        dataFile_.open(filePath, std::ios::out | std::ios::app);
        if (!dataFile_.is_open()) {
            LOGE("The file open fail");
            return;
        }
        LOGD("The file will write data size = (%u)", datas_.size());
        SetFileTitle();
    }
    for (auto& [_, v] : datas_) {
        for (auto& item : titles_) {
            auto it = v.find(item);
            if (it != v.end()) {
                dataFile_ << it->second;
            }
            dataFile_ << ",";
        }
        dataFile_ << "\n";
    }
    dataFile_.close();

    if (!running_) {
        std::map<uint32_t, std::map<std::string, std::string>>().swap(datas_);
    }
}

void TaskManager::SetFileTitle()
{
    if (firstSetTitle_) {
        for (const auto& [id, m] : datas_) {
            for (const auto& [k, _] : m) {
                titles_.insert(k);
            }
        }
        for (const auto& field : titles_) {
            dataFile_ << field << ",";
        }
        dataFile_ << "\n";
    }
    firstSetTitle_ = false;
}

void TaskManager::Stop(bool pause)
{
    isPause_ = pause;
    running_ = false;
    Resume();
    if (mainLoop_.joinable()) {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            running_ = false;
        }
        mainLoop_.join();
    }
    if (scheduleSaveDataTh_.joinable()) {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            running_ = false;
        }
        scheduleSaveDataCond_.notify_all();
        scheduleSaveDataTh_.join();
    }
    if (!pause) {
        LOGD("Start/Stop Collection End");
        threadPool_.Stop();
    }
}

void TaskManager::Wait()
{
    std::unique_lock<std::mutex> lock(finishMtx_);
    finishCond_.wait(lock, [this] { return !running_.load(); });
}

void TaskManager::CollectData(std::map<uint32_t, std::map<std::string, std::string>>& datas)
{
    std::unique_lock<std::mutex> lock(mtx_);
    for (auto& [k, v] : datas) {
        if (v.empty()) {
            continue;
        }
        datas_[k].merge(v);
    }
}

void TaskManager::GetProcessInfo(CommandType type, const ArgumentParser::ArgValue& value)
{
    if (type == CommandType::CT_PKG) {
        processName_ = std::get<std::string>(value);
        OHOS::SmartPerf::StartUpDelay sp;
        sp.GetPidByPkg(processName_, &processIds_);
    }

    if (type == CommandType::CT_PID) {
        processIds_ = std::to_string(std::get<int32_t>(value));
        const std::string getProcPkg = "cat /proc/" + processIds_ + "/cmdline";
        FILE *fd = popen(getProcPkg.c_str(), "r");
        if (fd == nullptr) {
            return;
        }
        char buf[1024] = {'\0'};
        while ((fgets(buf, sizeof(buf), fd)) != nullptr) {
            processName_ = buf;
        }
        if (pclose(fd) == -1) {
            LOGE("Error: Failed to close file");
            return;
        }
    }

    FPS::GetInstance().SetProcessId(processIds_);
    FPS::GetInstance().SetPackageName(processName_);
    Jitters::GetInstance().SetProcessId(processIds_);
    Jitters::GetInstance().SetPackageName(processName_);
    RAM::GetInstance().SetProcessId(processIds_);
    RAM::GetInstance().SetPackageName(processName_);
    CPU::GetInstance().SetProcessId(processIds_);
    CPU::GetInstance().SetPackageName(processName_);
    Navigation::GetInstance().SetProcessId(processIds_);
    AISchedule::GetInstance().SetProcessId(processIds_);
    Threads::GetInstance().SetProcessId(processIds_);
    Threads::GetInstance().SetPackageName(processName_);
    FileDescriptor::GetInstance().SetProcessId(processIds_);
    FileDescriptor::GetInstance().SetPackageName(processName_);
    Hiperf::GetInstance().SetProcessId(processIds_);
    Shader::GetInstance().SetPkgName(processName_);
}

void TaskManager::RegisterThreadLocal(ThreadLocal* local)
{
    std::unique_lock<std::mutex> lock(mtx_);
    threadLocals_.emplace_back(local);
}

std::string TaskManager::MapToString(std::map<std::string, std::string>& myMap)
{
    if (hapCollect_) {
        std::string appCollectMap = "t_index_info$$";
        std::vector<std::string> keysToFind = {"fps", "refreshrate", "currentNow", "ddrFrequency", "cpu0Frequency",
            "cpu1Frequency", "cpu2Frequency", "cpu3Frequency", "cpu4Frequency", "cpu5Frequency", "cpu6Frequency",
            "cpu7Frequency", "cpu8Frequency", "cpu9Frequency", "cpu10Frequency", "cpu11Frequency", "gpuFrequency",
            "pss", "swapPss", "shell_frame", "shell_back", "soc_thermal", "cpu0Usage", "cpu1Usage", "cpu2Usage",
            "cpu3Usage", "cpu4Usage", "cpu5Usage", "cpu6Usage", "cpu7Usage", "cpu8Usage", "cpu9Usage", "cpu10Usage",
            "cpu11Usage", "gpuLoad"};
        for (const auto& key : keysToFind) {
            if (auto iter = myMap.find(key); iter != myMap.end()) {
                appCollectMap += iter->first + ":" + iter->second + ",";
            }
        }
        return appCollectMap;
    } else {
        std::string str = "{ ";
        for (auto it = myMap.begin(); it != myMap.end(); ++it) {
            str += "\"" + it->first + "\": " + it->second + ", ";
        }
        const int subLen = 2;
        str.erase(str.end() - subLen, str.end());
        str += " }";
        return str;
    }
}

void TaskManager::ProcessCurrentBatch(std::map<std::string, std::string>& data)
{
    if (printDataInfo_) {
        std::cerr << std::endl;
        uint32_t index = 0;
        for (auto& [k, v] : data) {
            std::cerr << "order:" << index++ << " ";
            std::cerr << k << "=" << v << std::endl;
        }
    }

    if (ipcDataRecv_) {
        ipcCallback_(MapToString(data));
    }
}

void TaskManager::EnableIPCCallback()
{
    ipcDataRecv_ = true;
}

void TaskManager::SetIPCCallback(std::function<void(const std::string&)> callback)
{
    ipcCallback_ = callback;
}

void TaskManager::DisableIPCCallback()
{
    ipcDataRecv_ = false;
}

void TaskManager::SetHapFlag(bool flag)
{
    hapCollect_ = flag;
}

void TaskManager::SetNextTime(long long& nextTime)
{
    nextTime_ = &nextTime;
}

void TaskManager::ProcessOnceTask(bool start)
{
    for (auto& item : priorityTask_) {
        if (item == nullptr) {
            continue;
        }
        start ? item->StartExecutionOnce(isPause_.load()) : item->FinishtExecutionOnce(isPause_.load());
    }

    for (auto& item : normalTask_) {
        if (item == nullptr) {
            continue;
        }
        start ? item->StartExecutionOnce(isPause_.load()) : item->FinishtExecutionOnce(isPause_.load());
    }
}

void TaskManager::SetRecordState(bool record)
{
    if (record) {
        LOGD("Start saving data regularly");
        recordData_ = true;
        StartSaveFileThread();
    } else {
        LOGD("Turn off timing to save data");
        auto time = SAVE_DATA_INTERVAL_MINUTE * THE_MINUTE;
        SaveRegularly(time);
        recordData_ = false;

        if (scheduleSaveDataTh_.joinable()) {
            scheduleSaveDataTh_.join();
        }
    }
}

void TaskManager::DeleteTask(SpProfiler* task)
{
    if (task == nullptr) {
        return;
    }

    for (auto iter = normalTask_.begin(); iter != normalTask_.end(); ++iter) {
        if (task == *iter) {
            normalTask_.erase(iter);
            return;
        }
    }
    for (auto iter = priorityTask_.begin(); iter != priorityTask_.end(); ++iter) {
        if (task == *iter) {
            priorityTask_.erase(iter);
            return;
        }
    }
}

void TaskManager::InitDataCsv()
{
    if (!SPUtils::FileAccess(fileName_)) {
        char fileName[PATH_MAX] = {0x00};
        if (realpath(fileName_.c_str(), fileName) == nullptr) {
            LOGE("the file not exeit");
            return;
        }
        std::ofstream file(fileName_);
        if (file) {
            std::string chmodCmd = "chmod 777 " + fileName_;
            std::string cmdResult;
            SPUtils::LoadCmd(chmodCmd, cmdResult);
            file.close();
        } else {
            LOGE("Failed to creat file");
            return;
        }
    } else {
        char fileName[PATH_MAX] = {0x00};
        if (realpath(fileName_.c_str(), fileName) == nullptr) {
            LOGE("the file not exeit");
            return;
        }
        std::ofstream file(fileName_, std::ios::trunc);
        if (!file) {
            LOGE("Unable to open file");
            return;
        }
        file.close();
        LOGD("CreatPath already exists: %s", fileName_.c_str());
    }
}

ArgumentParser& TaskManager::GetArgumentParser()
{
    return parameter_;
}

void TaskManager::SetFileTitleFlag()
{
    firstSetTitle_ = true;
}

void TaskManager::ClearShaderFile()
{
    const std::string cmdRmShaderFile = CMD_COMMAND_MAP.at(CmdCommand::REMOVE) + "/data/local/tmp/" + processName_;
    std::string cmdResult = "";
    SPUtils::LoadCmd(cmdRmShaderFile, cmdResult);
}
}