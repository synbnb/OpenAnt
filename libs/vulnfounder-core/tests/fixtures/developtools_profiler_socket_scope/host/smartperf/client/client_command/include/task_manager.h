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

#ifndef TASK_MANAGER_H
#define TASK_MANAGER_H

#include "thread_pool.h"
#include "argument_parser.h"
#include "sp_profiler_factory.h"
#include "common.h"
#include <fstream>
#include <atomic>
#include <condition_variable>

namespace OHOS::SmartPerf {
class TaskManager;
class ThreadLocal {
public:
    ThreadLocal();
    ~ThreadLocal();
    std::map<uint32_t, std::map<std::string, std::string>> datasA_;
    std::map<uint32_t, std::map<std::string, std::string>> datasB_;
    std::atomic_bool switch_ {true};
};

class TaskManager {
public:
    explicit TaskManager(bool isIPC = false);

    void AddTask(const std::unordered_map<std::string, ArgumentParser::ArgValue>& argv);
    void AddTask(const std::string& argv);
    void AddTask(SpProfiler* task, bool priority);
    void AddTask(std::vector<std::string>& argv);
    void SetFilePath(const std::string& fileName, bool removeCurrentFile = true);
    void Start(bool record = true);
    void Stop(bool pause = false);
    void Pause();
    void Resume();
    void CollectData(std::map<uint32_t, std::map<std::string, std::string>>& datas);
    void WriteToCSV();
    void Wait();
    void RegisterThreadLocal(ThreadLocal* local);
    void EnableIPCCallback();
    void SetIPCCallback(std::function<void(const std::string&)> callback);
    void DisableIPCCallback();
    void SetHapFlag(bool flag);
    void SetNextTime(long long& nextTime);
    void SetRecordState(bool record);
    void DeleteTask(SpProfiler* task);
    void SetFileTitle();
    void InitDataCsv();
    ArgumentParser& GetArgumentParser();
    void SetFileTitleFlag();
    bool ThreadLock();
    void ClearShaderFile();

private:
    std::map<std::string, std::string> TaskFun(SpProfiler* pro, uint32_t batch, bool record);
    void GetProcessInfo(CommandType type, const ArgumentParser::ArgValue& value);
    std::string MapToString(std::map<std::string, std::string>& myMap);
    void StartSaveFileThread();
    void CollectThreadsData();
    void SaveRegularly(int32_t dataIndex);
    void ProcessCurrentBatch(std::map<std::string, std::string>& data);
    void ProcessOnceTask(bool start);
    void MainLoop();
    void GpuCounterProcess(const ArgumentParser::ArgValue& value);
    void SpecialKeyProcess(const std::string specKey);
    void HandleCommandType(CommandType cmdType, const ArgumentParser::ArgValue& val);
    ThreadPool threadPool_ {4};
    int32_t collectCount_ {-1};
    std::atomic_bool running_ {false};
    std::thread mainLoop_;
    std::set<SpProfiler *> normalTask_;
    std::set<SpProfiler *> priorityTask_;
    std::map<uint32_t, std::map<std::string, std::string>> datas_;
    std::mutex mtx_;
    std::string fileName_ {"/data/local/tmp/data.csv"};
    bool saveFlag_ {false};
    long long* nextTime_ {nullptr};

    std::condition_variable finishCond_;
    std::mutex finishMtx_;
    std::string processName_;
    std::string processIds_;
    bool printDataInfo_ {true};
    bool ipcDataRecv_ {false};
    std::vector<ThreadLocal*> threadLocals_ {4};
    std::ofstream dataFile_;
    std::set<std::string> titles_;

    std::thread scheduleSaveDataTh_;
    std::condition_variable scheduleSaveDataCond_;
    std::mutex scheduleSaveDataMtx_;
    std::function<void(const std::string&)> ipcCallback_ {nullptr};
    bool hapCollect_ {false};
    int32_t dataIndex_ {0};
    std::atomic_bool recordData_ {false};
    std::atomic_bool savingFile_ {false};
    std::atomic_bool isPause_ {false};
    bool firstSetTitle_ {true};
    ArgumentParser parameter_;
    std::atomic<bool> paused_{false};
    std::mutex pauseMutex_;
    std::condition_variable pauseCond_;
    long long baseTime_ = 0;
    int32_t collectTimes_ = 0;
};
}
#endif // TASK_MANAGER_H