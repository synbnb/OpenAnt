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

#include "cpu_info.h"

#include <string>
#include <regex>
#include <string_view>
#include <iomanip>
#include <unistd.h>
#include "sp_log.h"
namespace OHOS {
namespace SmartPerf {
std::map<std::string, std::string> CPUInfo::ItemData()
{
    Stop();
    std::map<std::string, std::string> result;
    std::istringstream stream(buffer_);
    std::string line;
    uint64_t cpu_cycles_total = 0;
    uint64_t instructions_total = 0;
    double cpi_total = 0.0;
    size_t cpu_cycles_count = 0;
    size_t instructions_count = 0;
    size_t cpi_count = 0;
    auto findData = [](const std::string& targetStr, auto& total, auto& count) {
        size_t count_start = targetStr.find_first_not_of(" \t");
        size_t count_end = targetStr.find(" ", count_start);
        std::string number_str = targetStr.substr(count_start, count_end - count_start);
        number_str.erase(std::remove(number_str.begin(), number_str.end(), ','), number_str.end());
        total += SPUtilesTye::StringToSometype<uint64_t>(number_str);
        ++count;
    };
    while (std::getline(stream, line)) {
        if (line.find(SPUtils::GetProductName() + "-cpu-cycles") != std::string::npos) {
            findData(line, cpu_cycles_total, cpu_cycles_count);
        }
        if (line.find(SPUtils::GetProductName() + "-instructions") != std::string::npos) {
            findData(line, instructions_total, instructions_count);
            CalculateCPIInfo(line, cpi_total, cpi_count);
        }
    }
    cpu_cycles_count == 0 ? "" :
        result[SPUtils::GetProductName() + "-cpu-cycles"] =
            std::to_string(static_cast<double>(cpu_cycles_total) / cpu_cycles_count);
    instructions_count == 0 ? "" :
        result[SPUtils::GetProductName() + "-instructions"] =
            std::to_string(static_cast<double>(instructions_total) / instructions_count);
    cpi_count == 0 ? "" : result["cycles per instruction"] = std::to_string(cpi_total / cpi_count);
    Start();
    LOGI("CPUInfo:ItemData map size(%u)", result.size());
    return result;
}

void CPUInfo::CalculateCPIInfo(const std::string line, double &cpiTotal, size_t &cpiCount)
{
    auto trim = [](std::string& s) {
        s.erase(0, s.find_first_not_of(" \t"));
        s.erase(s.find_last_not_of(" \t") + 1);
    };
    size_t comment_pos = line.find("|");
    if (comment_pos != std::string::npos) {
        std::string comment = line.substr(comment_pos + 1);
        trim(comment);
        size_t cpi_pos = comment.find("cycles per instruction");
        if (cpi_pos != std::string::npos) {
            size_t number_end = comment.find(" ", 0);
            std::string cpi_str = comment.substr(0, number_end);
            cpiTotal += SPUtilesTye::StringToSometype<double>(cpi_str);
            ++cpiCount;
        }
    }
}

void CPUInfo::StartExecutionOnce(bool isPause)
{
    (void)isPause;
    Stop();
    if (pids_.empty()) {
        hiperfCmd_ += "-a";
    } else {
        hiperfCmd_ += "-p " + pids_[0];
    }

    running_ = true;
    th_ = std::thread([this]() {
        while (running_) {
            buffer_.clear();
            std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(hiperfCmd_.c_str(), "r"), pclose);
            constexpr int lineSize = 1024;
            std::array<char, lineSize> chunk;
            while (fgets(chunk.data(), chunk.size(), pipe.get()) != nullptr) {
                buffer_.append(chunk.data());
            }

            if (!running_) {
                return;
            }
            std::unique_lock<std::mutex> lock(mtx_);
            cond_.wait(lock);
        }
    });
    sleep(1);
}

void CPUInfo::FinishtExecutionOnce(bool isPause)
{
    (void)isPause;
    running_ = false;
    Stop();
    cond_.notify_all();
    if (th_.joinable()) {
        th_.join();
    }
}

void CPUInfo::SetPids(const std::string& pids)
{
    pids_.clear();
    SPUtils::StrSplit(pids, " ", pids_);
}

void CPUInfo::Start()
{
    cond_.notify_all();
}

void CPUInfo::Stop()
{
    std::system("killall hiperf > /data/local/tmp/cpu_temp_error 2>&1");
    std::remove("/data/local/tmp/cpu_temp_error");
}
}
}