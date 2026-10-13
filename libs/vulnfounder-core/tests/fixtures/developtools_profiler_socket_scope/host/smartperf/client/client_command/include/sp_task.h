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
#ifndef SP_TASK_H
#define SP_TASK_H
#include <iostream>
#include <functional>
#include <vector>
#include <thread>
#include <future>
#include <map>
#include <mutex>
#include <climits>
#include "parameters.h"
#include "GpuCounter.h"
#include "GameEvent.h"
#include "task_manager.h"

namespace OHOS {
namespace SmartPerf {
enum class ExceptionMsg {
    NO_ERR,
    SESSION_ID_NULL,
    TASK_CONFIG_NULL,
    PACKAGE_NULL,
};

const std::map<ExceptionMsg, std::string> EXCEPTION_MSG_MAP = {
    { ExceptionMsg::NO_ERR, "NoErr" },
    { ExceptionMsg::SESSION_ID_NULL, "SessionIdNull" },
    { ExceptionMsg::TASK_CONFIG_NULL, "TaskConfigNull" },
    { ExceptionMsg::PACKAGE_NULL, "PackageNull" },
};

enum class ErrCode {
    OK,
    FAILED,
};
struct StuckNotification {
    bool isEffective = false;
    int fps = 0;
    long long frameTime = LLONG_MAX;
};
struct TaskInfo {
    std::string sessionId = "1";
    std::string packageName = "";
    std::string pid = "";
    std::vector<std::string> taskConfig = {};
    long long freq = 998;
    StuckNotification stuckInfo;
    bool isPrint = false;
};

class SPTask {
public:
    static SPTask &GetInstance()
    {
        static SPTask instance;
        return instance;
    }
    ErrCode InitTask(const std::string &recvStr);
    ErrCode StartTask(std::function<void(const std::string&)> msgTask);
    ErrCode StopTask();
    bool CheckTcpParam(const std::string& str, std::string &errorInfo);
    void CreatPath(const std::string& path);
    void InitDataFile();
    void StopGetInfo();
    ErrCode StartRecord();
    ErrCode StopRecord();
    bool GetRecordState();
    void SetRecordState(bool status);
    std::string GetCsvTitle();
    void SetAppCmd(const std::string &recvBuf);
    TaskInfo GetCurTaskInfo();
    void SetAppInitFlag();
    void SetStartFlag();
    void ClearStopFlag();

private:
    void KillHiperfCmd();
    int GetCurrentBattary();
    void SetProfilerPid();
    std::map<std::string, std::string> SetTaskInfo();
    void EnablePrint();

private:
    TaskInfo curTaskInfo;
    long long startTime = 0;
    std::thread thread;
    bool isRunning = false;
    bool isInit = false;
    std::mutex asyncDataMtx;
    const std::string baseOutPath = "/data/local/tmp/smartperf";
    long long startCaptuerTime = 0;
    GpuCounter &gpuCounter = GpuCounter::GetInstance();
    GameEvent &gameEvent = GameEvent::GetInstance();
    bool recordState = false;
    long long nextTime = 0;
    int battaryStart = 0;
    int battaryEnd = 0;
    std::string csvTitle = "";
    int stdOutLog = -1;
    std::shared_ptr<TaskManager> taskMgr_ {nullptr};
};
}
}

#endif