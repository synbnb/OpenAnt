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
#include "include/GetLog.h"
#include "include/sp_utils.h"
#include "include/smartperf_command.h"
#include <fstream>
#include <filesystem>
#include <vector>
#include <chrono>
#include <ctime>
namespace OHOS {
namespace SmartPerf {
void GetLog::GetHilogInMemory(std::vector<std::filesystem::path> &fileList)
{
    // Get current hilog in "hilog" command
    std::string hilogTmp = hilogFileDir + "hilogTmp";
    std::string cmd = CMD_COMMAND_MAP.at(CmdCommand::GET_HILOG) + hilogTmp;
    std::string cmdResult;
    if (!SPUtils::LoadCmd(cmd, cmdResult)) {
        WLOGE("Failed to GetHilogCommand files: %s", hilogTmp.c_str());
    }
    if (std::filesystem::exists(hilogTmp)) {
        currentLogSize += std::filesystem::file_size(hilogTmp);
        fileList.push_back(hilogTmp);
    }
}

void GetLog::RemoveLogFile()
{
    // Process before and after send
    SPUtils::RemoveDirOrFile(logFilePath);
    SPUtils::RemoveDirOrFile(hilogFileDir);
    SPUtils::RemoveDirOrFile(daemonLogFileDir);

    currentLogSize = 0;
}

void GetLog::GenerateDaemonLogFile()
{
    const std::string preLogFileName = "log.";
    std::filesystem::path dirPath(LOG_FILE_DIR);    // Log file directory
    std::vector<std::filesystem::path> files;       // Log file vector to tar

    SPUtils::CreateDir(daemonLogFileDir);                    // Create daemonLog directory

    // Save current working directory to restore it later
    // Change directory to handle relative paths in tar operations
    std::string originPath;
    if (std::filesystem::current_path().string().empty()) {
        WLOGE("Failed to get current working directory");
        return;
    }
    originPath = std::filesystem::current_path().string();
    std::filesystem::current_path(LOG_FILE_DIR);

    // Get all log files in LOG_FILE_DIR
    for (const auto& entry : std::filesystem::directory_iterator(dirPath)) {
        if (std::filesystem::is_regular_file(entry)) {
            if (entry.path().filename().string().substr(0, preLogFileName.length()) != preLogFileName) {
                continue;  // Skip files that don't start with "log."
            }
            files.push_back(entry.path());
        }
    }

    // Sort log files by last write time
    std::sort(files.begin(), files.end(), [](const auto& a, const auto& b) {
        return std::filesystem::last_write_time(a) > std::filesystem::last_write_time(b);
    });

    // Build tar command with relative paths only, respecting size limit
    std::string cpCommand = "";
    for (const auto& file : files) {
        uintmax_t fileSize = std::filesystem::file_size(file);
        if (currentLogSize + fileSize > logMaxSize) {
            break; // Stop if adding this file would exceed the limit
        }
        currentLogSize += fileSize;
        std::string filename = file.filename().string();
        cpCommand += filename + " ";
    }
    cpCommand += daemonLogFileDir;
    SPUtils::CopyFiles(cpCommand);

    std::filesystem::current_path(originPath.c_str());
    WLOGI("Created tar archive of daemonLog files successfully");
}

std::time_t to_time_t(const std::filesystem::file_time_type &ftime)
{
    auto systemTime = std::chrono::time_point_cast<std::chrono::system_clock::duration>
        (ftime - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
    return std::chrono::system_clock::to_time_t(systemTime);
}

void GetLog::GetHilogInData(std::vector<std::filesystem::path> &otherFiles,
    std::vector<std::filesystem::path> &logFiles)
{
    std::filesystem::path dirPath(systemHilogFileDir);

    try {
        if (std::filesystem::exists(dirPath)) {
            WLOGI("Success read hilog dir");
        }
    } catch (const std::filesystem::filesystem_error &e) {
        WLOGE("GetHilogFiles error: %s", e.what());
        return;
    }

    for (const auto& entry : std::filesystem::directory_iterator(dirPath)) {
        if (!std::filesystem::is_regular_file(entry)) {
            continue;
        }

        std::string extension = entry.path().extension().string();
        if (extension == ".log" || extension == ".zip") {
            otherFiles.push_back(entry.path());
            continue;
        }

        if (extension != ".gz") {
            continue;
        }

        // Handle .gz files
        auto fileTime = std::filesystem::last_write_time(entry.path());
        auto fileTimeT = to_time_t(fileTime);
        auto nowT = to_time_t(std::filesystem::file_time_type::clock::now());
        if (std::localtime(&fileTimeT) == nullptr || std::localtime(&nowT) == nullptr) {
            WLOGE("Get local time is null");
            return;
        }
        std::tm* fileTm = std::localtime(&fileTimeT);
        std::tm* nowTm = std::localtime(&nowT);
        if (fileTm == nullptr || nowTm == nullptr) {
            WLOGE("Get local time ptr is null");
            return;
        }

        bool isSameDay = (fileTm->tm_year == nowTm->tm_year) &&
            (fileTm->tm_mon == nowTm->tm_mon) &&
            (fileTm->tm_mday == nowTm->tm_mday);

        if (isSameDay) {
            logFiles.push_back(entry.path());
        }
    }
}

void GetLog::GenerateHilogFile()
{
    std::vector<std::filesystem::path> filesLog;            // Log file vector to tar
    std::vector<std::filesystem::path> filesOther;          // Other file vector to tar

    SPUtils::CreateDir(hilogFileDir);
    std::string originPath;
    if (std::filesystem::current_path().string().empty()) {
        WLOGE("Failed to get current working directory");
        return;
    }
    originPath = std::filesystem::current_path().string();
    GetHilogInMemory(filesLog);
    GetHilogInData(filesOther, filesLog);

    if (filesLog.empty() && filesOther.empty()) {
        WLOGE("Failed to get hilog files");
        return;
    }

    // Sort hilog files by last write time
    std::sort(filesLog.begin(), filesLog.end(), [](const auto& a, const auto& b) {
        return std::filesystem::last_write_time(a) > std::filesystem::last_write_time(b);
    });

    // cd LOG_FILE_DIR
    std::filesystem::current_path(systemHilogFileDir);
    // Build tokar command with relative paths only
    std::string cpCommand = "";
    for (const auto& file : filesOther) {
        uintmax_t fileSize = std::filesystem::file_size(file);
        if (currentLogSize + fileSize > logMaxSize) {
            break; // Stop if adding this file would exceed the limit
        }
        currentLogSize += fileSize;
        std::string filename = file.filename().string();
        cpCommand += filename + " ";
    }
    for (const auto& file : filesLog) {
        uintmax_t fileSize = std::filesystem::file_size(file);
        if (currentLogSize + fileSize > logMaxSize) {
            break; // Stop if adding this file would exceed the limit
        }
        currentLogSize += fileSize;
        std::string filename = file.filename().string();
        cpCommand += filename + " ";
    }
    cpCommand += hilogFileDir;
    SPUtils::CopyFiles(cpCommand);

    std::filesystem::current_path(originPath.c_str());
    WLOGI("Created tar archive of hilog files successfully");
}

void GetLog::TarLogFile()
{
    GenerateDaemonLogFile();
    GenerateHilogFile();

    std::string originPath;
    if (std::filesystem::current_path().string().empty()) {
        WLOGE("Failed to get current working directory");
        return;
    }
    originPath = std::filesystem::current_path().string();

    // cd LOG_FILE_DIR
    std::filesystem::current_path(LOG_FILE_DIR);

    // Check if directories exist
    if (!std::filesystem::exists("daemonLog")) {
        WLOGE("One or both directories do not exist");
        std::filesystem::current_path(originPath.c_str());
        return;
    }

    // Build tar command with relative paths
    std::string tarCommand = logFilePath + " hilog daemonLog";
    SPUtils::TarFiles(tarCommand);

    // Restore original working directory
    std::filesystem::current_path(originPath.c_str());
    WLOGI("Created tar archive of log files successfully");
}

std::map<std::string, std::string> GetLog::ItemData()
{
    // Remove old log tar file
    RemoveLogFile();
    // Create tar archive of log files
    TarLogFile();
    // Return empty map to satisfy interface
    return std::map<std::string, std::string>();
}

} // namespace SmartPerf
} // namespace OHOS