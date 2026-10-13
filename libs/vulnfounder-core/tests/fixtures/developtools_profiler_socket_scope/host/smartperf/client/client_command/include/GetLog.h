/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
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

#ifndef GETLOG_H
#define GETLOG_H
#include "sp_profiler.h"
#include "sp_log.h"
#include <string>
#include <filesystem>
namespace OHOS {
namespace SmartPerf {
class GetLog : public SpProfiler {
public:
    std::map<std::string, std::string> ItemData() override;
    static GetLog &GetInstance()
    {
        static GetLog instance;
        return instance;
    }
    void RemoveLogFile();

private:
    GetLog() {};
    GetLog(const GetLog &);
    GetLog &operator = (const GetLog &);
    void TarLogFile();
    int GetCurrentPath(char *currentPath);
    void GetHilogInMemory(std::vector<std::filesystem::path> &fileList);
    void GetHilogInData(std::vector<std::filesystem::path> &otherFiles, std::vector<std::filesystem::path> &logFiles);
    void GenerateHilogFile();
    void GenerateDaemonLogFile();

    int logFileSocket = -1;
    int logFileSocketPort = -1;
    const std::string systemHilogFileDir = "/data/log/hilog/";
    const std::string hilogFileDir = LOG_FILE_DIR + "hilog/";
    const std::string daemonLogFileDir = LOG_FILE_DIR + "daemonLog/";
    const std::string logFilePath = LOG_FILE_DIR + "logfile.tar.gz";
    static const uintmax_t logMaxSize = 52428800; // 50MB = 50 * 1024 * 1024
    uintmax_t currentLogSize = 0;
};
}
}
#endif // NETWORK_H
