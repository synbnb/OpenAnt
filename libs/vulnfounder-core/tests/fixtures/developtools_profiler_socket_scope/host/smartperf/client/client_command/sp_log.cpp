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

#include "sp_log.h"
#include "securec.h"
#include <sys/stat.h>
#include <string>
#include <sstream>
#include <iostream>
#include <cstring>
#include <cstdint>
#include <dirent.h>
#include <unistd.h>
#include <mutex>
#include <ctime>
#include <fstream>
#include <vector>
#include <filesystem>
#include <iomanip>
#include <chrono>
#include <regex>
#include <thread>
#include <cstdlib>
#include <cstdio>
#include "include/smartperf_command.h"

#ifdef HI_LOG_ENABLE
#include "hilog/log.h"
#endif

namespace OHOS {
namespace SmartPerf {
const int32_t LOG_MAX_LEN = 10000;
const long long MAX_FILE_SIZE = 4 * 1024 * 1024;  // 4MB
const double MAX_FILE_KEEP_TIME = 60 * 60 * 24 * 7; // 7days
const int MAX_FILE_COUNT = 256;
const mode_t LOG_FILE_MODE = 0755;
std::mutex g_mtx;
std::string g_currentLogFilePath;
std::string g_currentDate;
bool g_writeEnable = false;

static void SpLogOut(SpLogLevel logLevel, const char *logBuf)
{
#ifdef HI_LOG_ENABLE
    LogLevel hiLogLevel = LOG_INFO;
    switch (logLevel) {
        case SP_LOG_DEBUG:
            hiLogLevel = LOG_DEBUG;
            break;
        case SP_LOG_INFO:
            hiLogLevel = LOG_INFO;
            break;
        case SP_LOG_WARN:
            hiLogLevel = LOG_WARN;
            break;
        case SP_LOG_ERROR:
            hiLogLevel = LOG_ERROR;
            break;
        default:
            break;
    }
    (void)HiLogPrint(LOG_CORE, hiLogLevel, LOG_DOMAIN, "SP_daemon", "%{public}s", logBuf);
#else
    switch (logLevel) {
        case SP_LOG_DEBUG:
            printf("[D]%s\n", logBuf);
            break;
        case SP_LOG_INFO:
            printf("[I]%s\n", logBuf);
            break;
        case SP_LOG_WARN:
            printf("[W]%s\n", logBuf);
            break;
        case SP_LOG_ERROR:
            printf("[E]%s\n", logBuf);
            break;
        default:
            break;
    }
#endif
}

static bool EnsureLogDirectoryExists()
{
    if (!std::__fs::filesystem::exists(LOG_FILE_DIR)) {
        LOGD("Try create dir: %s", LOG_FILE_DIR.c_str());
        try {
            if (mkdir(LOG_FILE_DIR.c_str(), S_IRWXU | S_IRWXG | S_IRWXO) != 0) {
                LOGE("Failed to create log directory: %s", strerror(errno));
                return false;
            }

            if (!std::__fs::filesystem::exists(LOG_FILE_DIR)) {
                LOGE("Failed to create log directory.");
                return false;
            }
        } catch (const std::exception& e) {
            LOGE("Exception while creating log directory: %s", e.what());
            return false;
        }
    }

    return true;
}

static std::string GetCurrentDate()
{
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm* tm = std::localtime(&time);
    if (tm == nullptr) {
        return "";
    }

    std::ostringstream oss;
    oss << std::put_time(tm, "%Y%m%d");
    return oss.str();
}
static std::string GetCurrentLogFilePath(int maxLogNumber)
{
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm* tm = std::localtime(&time);
    if (tm == nullptr) {
        return "";
    }
    std::ostringstream oss;
    oss << LOG_FILE_DIR << "log." << maxLogNumber << "." <<
        g_currentDate << "-" << std::put_time(tm, "%H%M%S");
    return oss.str();
}
static bool IsFilePathValid(const std::string& filePath)
{
    char filePathChar[PATH_MAX] = {0x00};
    if ((realpath(filePath.c_str(), filePathChar) == nullptr)) {
        LOGE("Log file %s is not exist.", filePath.c_str());
        return false;
    }
    std::ifstream file(filePathChar, std::ios::binary | std::ios::ate);
    if (file.is_open()) {
        return file.tellg() <= MAX_FILE_SIZE;
    }
    return false;
}

static int CheckFileNameAndGetNumber(const std::string& fileName, const std::string& date, bool* currentDateFlag)
{
    std::regex pattern(R"(^log\.(\d+)\.(\d{8})-\d{6}$)");
    std::smatch matches;

    if (std::regex_match(fileName, matches, pattern)) {
        std::string fileDate = matches[2].str();
        if (fileDate == date) {
            *currentDateFlag = true;
        }
        return SPUtilesTye::StringToSometype<int>(matches[1].str());
    }

    return 0;
}

static bool Chmod(const std::string& sourceFilePath, mode_t mode)
{
    int retCode = chmod(sourceFilePath.c_str(), mode);
    if (retCode != 0) {
        LOGE("Failed to set %s permission, error code %d.", sourceFilePath.c_str(), retCode);
        return false;
    }

    return true;
}

static void TarFile(const std::string& sourceFileName)
{
    std::ostringstream compressedFilePath;
    compressedFilePath << LOG_FILE_DIR << sourceFileName << ".tar.gz";

    std::string tarStr = compressedFilePath.str() + " -C " + LOG_FILE_DIR + " " + sourceFileName;
    std::string tarCommand = CMD_COMMAND_MAP.at(CmdCommand::TAR) + tarStr;
    std::string cmdResult;
    if (!SPUtils::LoadCmd(tarCommand, cmdResult)) {
        LOGE("Failed to compress file %s", sourceFileName.c_str());
        return;
    }

    Chmod(compressedFilePath.str(), LOG_FILE_MODE);

    tarCommand = CMD_COMMAND_MAP.at(CmdCommand::REMOVE) + LOG_FILE_DIR + sourceFileName;
    if (!SPUtils::LoadCmd(tarCommand, cmdResult)) {
        LOGE("Failed to delete original file %s", sourceFileName.c_str());
        return;
    }

    LOGD("Successfully compressed and deleted file: %s", sourceFileName.c_str());
    return;
}

static bool GetLogFilePath()
{
    std::string date = GetCurrentDate();
    if (date == "") {
        LOGE("Get current date failed");
        return false;
    }
    if ((date == g_currentDate) && IsFilePathValid(g_currentLogFilePath)) {
        return true;
    }
    LOGE("Current log file path invalid: %s", g_currentLogFilePath.c_str());
    g_currentDate = date;
    std::string fileName;
    bool currentDateFlag = false;
    int fileNumber = 0;
    for (const auto& entry : std::__fs::filesystem::directory_iterator(LOG_FILE_DIR)) {
        if (entry.is_regular_file()) {
            fileName = entry.path().filename().string();
            fileNumber = CheckFileNameAndGetNumber(fileName, date, &currentDateFlag);
            if (fileNumber != 0) {
                break;
            }
        }
    }
    if (fileNumber == 0) {
        g_currentLogFilePath = GetCurrentLogFilePath(1);
        if (g_currentLogFilePath == "") {
            LOGE("Get current log file data is null");
            return false;
        }
        return true;
    }
    std::string filePath = LOG_FILE_DIR + fileName;
    if (currentDateFlag && IsFilePathValid(filePath)) {
        g_currentLogFilePath = filePath;
        return true;
    }
    TarFile(fileName);
    if (fileNumber >= MAX_FILE_COUNT) {
        LOGE("Log file full!");
        return false;
    }
    g_currentLogFilePath = GetCurrentLogFilePath(fileNumber + 1);
    return true;
}

static void WriteMessage(const char* logMessage)
{
    bool chmodFlag = !std::__fs::filesystem::exists(g_currentLogFilePath);

    char logFilePathChar[PATH_MAX] = {0x00};
    if ((realpath(g_currentLogFilePath.c_str(), logFilePathChar) == nullptr)) {
        errno_t result = strncpy_s(logFilePathChar, PATH_MAX,
            g_currentLogFilePath.c_str(), g_currentLogFilePath.size());
        if (result != 0) {
            LOGE("strncpy_s failed with error: %d", result);
            return;
        }
        LOGI("Log file %s is not exist, will create", g_currentLogFilePath.c_str());
    }

    std::ofstream logFile(logFilePathChar, std::ios::app);
    if (logFile.is_open()) {
        if (chmodFlag) {
            if (!Chmod(logFilePathChar, LOG_FILE_MODE)) {
                logFile.close();
                return;
            }
        }

        auto now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);
        std::tm* tm = std::localtime(&time);
        if (tm == nullptr) {
            LOGE("Write Message get current data is null");
            logFile.close();
            return;
        }

        std::ostringstream timeStamp;
        timeStamp << std::put_time(tm, "[%H:%M:%S]");
        logFile << timeStamp.str() << logMessage << std::endl;

        logFile.close();
    } else {
        LOGE("Unable to open log file for writing: %s", logFilePathChar);
    }

    return;
}

void EnableWriteLogAndDeleteOldLogFiles()
{
    g_writeEnable = true;
    std::lock_guard<std::mutex> lock(g_mtx);

    if (!EnsureLogDirectoryExists()) {
        return;
    }

    DIR* dir = opendir(LOG_FILE_DIR.c_str());
    if (dir == nullptr) {
        LOGE("Failed to open log directory: %s", LOG_FILE_DIR.c_str());
        return;
    }

    struct dirent* entry;
    time_t currentTime = time(nullptr);

    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        std::string filePath = LOG_FILE_DIR + entry->d_name;
        char filePathChar[PATH_MAX] = {0x00};
        if ((realpath(filePath.c_str(), filePathChar) == nullptr)) {
            LOGE("Log file %s is not exist.", filePath.c_str());
            continue;
        }

        struct stat fileStat = {0};
        if (stat(filePathChar, &fileStat) != 0) {
            LOGE("Failed to get stats for file: %s", filePathChar);
            continue;
        }

        double diffSeconds = difftime(currentTime, fileStat.st_mtime);
        if (diffSeconds > MAX_FILE_KEEP_TIME) {
            if (remove(filePathChar) == 0) {
                LOGD("Deleted file: %s, last modified: %.2f seconds ago", filePathChar, diffSeconds);
            } else {
                LOGE("Failed to delete file: %s", filePathChar);
            }
        }
    }

    closedir(dir);
}

void EscapeForCSV(std::string str)
{
    std::string escapedStr;
    for (char ch : str) {
        if (ch == '"') {
            escapedStr += "\"\"";
        } else if (ch == ',' || ch == '\n' || ch == '\r') {
            escapedStr += '"';
            escapedStr += ch;
            escapedStr += '"';
        } else {
            escapedStr += ch;
        }
    }
    str = escapedStr;
}

void SpLog(SpLogLevel logLevel, bool isWriteLog, const char *fmt, ...)
{
    if (fmt == nullptr) {
        SpLogOut(logLevel, "SP log format string is NULL.");
        return;
    }
    size_t fmtLength = strlen(fmt);
    if (fmtLength == 0) {
        SpLogOut(logLevel, "SP log format string is empty.");
        return;
    }
    char logBuf[LOG_MAX_LEN] = {0};
    int32_t ret = 0;
    va_list arg;
    va_start(arg, fmt);
    va_list bkArg;
    va_copy(bkArg, arg);
    ret = vsnprintf_s(logBuf, sizeof(logBuf), sizeof(logBuf) - 1, fmt, bkArg);
    va_end(bkArg);
    va_end(arg);
    if (ret < 0) {
        SpLogOut(logLevel, "SP log length error.");
        return;
    }
    if (ret >= static_cast<int32_t>(sizeof(logBuf) - 1)) {
        SpLogOut(logLevel, "SP log error: log message truncated.");
        return;
    }
    std::string logStr(logBuf);
    EscapeForCSV(logStr);
    SpLogOut(logLevel, logStr.c_str());

    if (!isWriteLog) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_mtx);

    if (!g_writeEnable || !EnsureLogDirectoryExists() || !GetLogFilePath()) {
        return;
    }

    WriteMessage(logStr.c_str());
    return;
}
} // namespace SmartPerf
} // namespace OHOS