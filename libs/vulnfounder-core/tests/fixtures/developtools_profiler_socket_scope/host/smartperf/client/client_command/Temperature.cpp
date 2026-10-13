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
#include <string>
#include "include/sp_utils.h"
#include <dirent.h>
#include "include/Temperature.h"
#include "include/sp_log.h"
namespace OHOS {
namespace SmartPerf {
std::map<std::string, std::string> Temperature::ItemData()
{
    DIR *dp = opendir(thermalBasePath.c_str());
    struct dirent *dirp;
    std::vector<std::string> dirs;
    if (dp == nullptr) {
        LOGE("Open directory failed!");
        return {};
    }
    while ((dirp = readdir(dp)) != nullptr) {
        if (strcmp(dirp->d_name, ".") != 0 && strcmp(dirp->d_name, "..") != 0) {
            std::string filename(dirp->d_name);
            if (filename.find("cooling") == std::string::npos) {
                dirs.push_back(SPUtils::IncludePathDelimiter(thermalBasePath) + filename);
            }
        }
    }
    closedir(dp);
    std::map<std::string, std::string> result;
    for (auto dir : dirs) {
        std::string dirType = dir + "/type";
        std::string dirTemp = dir + "/temp";

        if (!SPUtils::FileAccess(dirType)) {
            continue;
        }

        std::string type;
        std::string temp;
        SPUtils::LoadFile(dirType, type);
        SPUtils::LoadFile(dirTemp, temp);
        GetTempInfos(result, type, temp);
    }

    LOGI("Temperature:ItemData map size(%u)", result.size());
    return result;
}

void Temperature::GetTempInfos(std::map<std::string, std::string> &result, const std::string& type,
    const std::string& temp)
{
    for (auto node : collectNodes) {
        if (!strcmp(type.c_str(), node.c_str())) {
            float t = SPUtilesTye::StringToSometype<float>(temp);
            if (node == "gpu" || node.find("cluster") != std::string::npos) {
                result[type] = std::to_string(t);
            } else if (node == "drmos_gpu_npu" || node == "npu_thermal") {
                result["npu_thermal"] = std::to_string(t / 1e3);
            } else {
                result[type] = std::to_string(t / 1e3);
            }
        }
    }
}
}
}
