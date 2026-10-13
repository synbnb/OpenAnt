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
#ifndef SP_CSV_UTIL_H
#define SP_CSV_UTIL_H
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <climits>
#include <cstdlib>
#include <map>
#include "common.h"
#include "sp_data.h"
#include "sp_utils.h"
#include "sp_task.h"
#include <sys/stat.h>
#include <sys/statfs.h>
#include "sp_log.h"
#include "hisysevent.h"
#include <vector>
#include <dirent.h>
namespace OHOS {
namespace SmartPerf {
class SpCsvUtil {
public:
    static void WriteCsv(const std::string &path, std::vector<std::map <std::string, std::string>>& vmap)
    {
        std::ofstream outFile;
        std::string cmdResult;
        SPUtils::LoadCmd(CMD_COMMAND_MAP.at(CmdCommand::USER_PERMISSIONS), cmdResult);
        outFile.open(path.c_str(), std::ios::out | std::ios::trunc);
        if (SPUtils::GetPathPermissions(path) && outFile.is_open() && path == "/data/local/tmp/data.csv" &&
            (cmdResult == "root" || cmdResult == "shell"))  {
            std::string cmd = "chmod 777 " + path;
            SPUtils::LoadCmd(cmd, cmdResult);
        }
        int i = 0;
        for (const auto &vectorMap : vmap) {
            std::string lineContent = "";
            for (const auto &map : vectorMap) {
                lineContent += map.second + ",";
            }
            if (i == 0) {
                std::string csvTitle = "";
                csvTitle = SetDataCsvTitle(vectorMap);
                csvTitle.pop_back();
                outFile << csvTitle << std::endl;
            }
            lineContent.pop_back();
            outFile << lineContent << std::endl;
            ++i;
        }
        ReportFileWriteEvent(path);
        outFile.close();
    }
    static void WriteCsvH(std::map<std::string, std::string>& vmap)
    {
        const std::string outGeneralPath = "/data/local/tmp/smartperf/1/t_general_info.csv";
        std::ofstream outFile(outGeneralPath, std::ios::out | std::ios::trunc);
        if (!outFile.is_open()) {
            std::cout << "Error opening file!" << std::endl;
            return;
        }
        for (const auto& [key, value] : vmap) {
            outFile << key << "," << value << std::endl;
        }
        ReportFileWriteEvent(outGeneralPath);
        outFile.close();
    }
    static std::string SetDataCsvTitle(const std::map <std::string, std::string> &map)
    {
        std::string csvTitle = SPTask::GetInstance().GetCsvTitle();
        if (csvTitle.empty()) {
            for (const auto &iter : map) {
                csvTitle += iter.first + ",";
            }
        }
        return csvTitle;
    }

    static bool IsUiTestCreatedFile(const std::string &fileName)
    {
        if (fileName == "t_general_info.csv" || fileName == "t_index_info.csv" || fileName == "data.csv") {
            return true;
        }
        return false;
    }

    static uint64_t GetFileSize(const std::string &filePath)
    {
        struct stat fileStat;
        uint64_t fileSize = stat(filePath.c_str(), &fileStat) ? 0 : static_cast<uint64_t>(fileStat.st_size);
        return fileSize;
    }

    static uint64_t GetUiTestCreatedFileSize(const std::string &newFilePath, std::string &dirName)
    {
        uint64_t createdFileSize = 0;
        DIR* dir = opendir(dirName.c_str());
        if (!dir) {
            LOGE("Open dir %{public}s failed.", dirName.c_str());
            return createdFileSize;
        }
        if (newFilePath != "") {
            createdFileSize += GetFileSize(newFilePath);
        }
        struct dirent* file;
        while ((file = readdir(dir)) != nullptr) {
            if (file->d_type == DT_REG && IsUiTestCreatedFile(file->d_name)) {
                std::string filePath = dirName + "/" + file->d_name;
                if (filePath != newFilePath) {
                    createdFileSize += GetFileSize(filePath);
                }
            }
        }
        closedir(dir);
        return createdFileSize;
    }

    static void ReportFileWriteEvent(const std::string &newFilePath)
    {
        std::string partitionName = "/data";
        std::string dirName = "/data/local/tmp";
        struct statfs partitionStat;
        
        if (statfs(partitionName.c_str(), &partitionStat) != 0) {
            LOGE("Get remain partition size failed, partitionName = %{public}s", partitionName.c_str());
            return;
        }
        constexpr double units = 1024.0;
        double remainPartitionSize = (static_cast<double>(partitionStat.f_bfree) / units) *
                                     (static_cast<double>(partitionStat.f_bsize) / units);
        uint64_t createdFileSize = GetUiTestCreatedFileSize(newFilePath, dirName);
        std::vector<std::string> filePaths = { dirName };
        std::vector<uint64_t> fileSizes = { createdFileSize };
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::FILEMANAGEMENT, "USER_DATA_SIZE",
            HiviewDFX::HiSysEvent::EventType::STATISTIC,
            "COMPONENT_NAME", "SP_daemon",
            "PARTITION_NAME", partitionName,
            "REMAIN_PARTITION_SIZE", remainPartitionSize,
            "FILE_OR_FOLDER_PATH", filePaths,
            "FILE_OR_FOLDER_SIZE", fileSizes);

        LOGD("partitionName = %s", partitionName.c_str());
        LOGD("remainPartitionSize = %lld", remainPartitionSize);
    }
};
}
}

#endif // SP_CSV_UTILS_H
