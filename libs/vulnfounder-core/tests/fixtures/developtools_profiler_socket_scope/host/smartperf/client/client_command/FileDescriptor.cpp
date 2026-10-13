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
#include <filesystem>
#include <iostream>
#include "include/FileDescriptor.h"
#include "include/sp_utils.h"
#include "include/sp_log.h"

namespace fs = std::filesystem;
namespace OHOS {
namespace SmartPerf {
const size_t FDSRESERVE_SIZE = 512;
const size_t FDTOTALSRESERVE_SIZE = 1024;
std::map<std::string, std::string> FileDescriptor::ItemData()
{
    std::map<std::string, std::string> result;
    std::string& fds = result["fds"];
    std::string& fdTotal = result["fdTotal"];
    fds.reserve(FDSRESERVE_SIZE);
    fdTotal.reserve(FDTOTALSRESERVE_SIZE);
    idNum = processId.size();
    for (size_t i = 0; i < idNum; i++) {
        GetFds(processId[i], fds, fdTotal);
    }
#ifndef FUZZ_TEST
    LOGD("FileDescriptor::ItemData %s %s", fds.c_str(), fdTotal.c_str());
#endif
    return result;
}

void FileDescriptor::SetPackageName(const std::string &pName)
{
    packageName = pName;
}

void FileDescriptor::SetProcessId(const std::string &pid)
{
    processId.clear();
    SPUtils::StrSplit(pid, " ", processId);
}

void FileDescriptor::GetFds(const std::string &pid, std::string &fds, std::string &fdTotal)
{
    std::string directoryPath = "/proc/";
    directoryPath.append(pid).append("/fd/");
    int cnt = 0;
    std::error_code ec;
    if (fs::exists(directoryPath) && fs::is_directory(directoryPath)) {
        fs::directory_iterator dir_iter(directoryPath, ec);
        if (ec) {
#ifndef FUZZ_TEST
            LOGD("Get fds info fail (%s)", ec.message().c_str());
            fds.append(pid).append(":").append("0");
            fdTotal.append(pid).append(":").append("0").append("|");
#endif
            return;
        }
        fds.append(pid).append(":");
        for (const auto &entry : dir_iter) {
            std::string fileSymlink = fs::read_symlink(directoryPath + entry.path().filename().string(), ec);
            if (ec) {
#ifndef FUZZ_TEST
                LOGD("Get (%s) info fail (%s)", entry.path().c_str(), ec.message().c_str());
                break;
#endif
            }
            ++cnt;
            fds.append(entry.path().filename().string()).append("->").append(fileSymlink).append(" ");
        }
        fdTotal.append(pid).append(":").append(std::to_string(cnt));
        if (idNum > 1) {
            fds.append("|");
            fdTotal.append("|");
        }
    } else {
        processId.erase(std::remove(processId.begin(), processId.end(), pid), processId.end());
#ifndef FUZZ_TEST
        LOGD("(%s) Not exist.", directoryPath.c_str());
#endif
    }
}

void FileDescriptor::SetProcessIdForFuzzTest(const std::vector<std::string> &pid)
{
    processId = pid;
}
}
}