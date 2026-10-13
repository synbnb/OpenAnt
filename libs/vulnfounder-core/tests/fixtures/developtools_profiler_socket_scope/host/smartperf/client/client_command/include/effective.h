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

#ifndef EFFECTIVE_H
#define EFFECTIVE_H

#include "sp_profiler.h"
#include <string>
#include <thread>
#include <climits>
namespace OHOS {
namespace SmartPerf {
class Effective : public SpProfiler {
public:
    static Effective &GetInstance()
    {
        static Effective instance;
        return instance;
    }
    std::map<std::string, std::string> ItemData() override;
    int fps_ {0};
    long long frameTime_ {LLONG_MAX};

private:
    bool CheckCounterId();
    std::thread ThreadGetHiperf(long long timeStamp);
    void GetHiperf(const std::string &traceName);
    std::string SetHiperf(const std::string &traceName);

    int64_t startCaptuerTime_ {0};
    int requestId_ {1};
    std::string strOne_ = R"(hiprofiler_cmd \
        -c - \
        -o /data/local/tmp/)";
    std::string strTwo_ = R"(.htrace \
            -t 5 \
            -s \
            -k \
        <<CONFIG)";
    
    std::string strThree_ = R"(request_id: )";
    std::string strFour_ = R"( session_config {
        buffers {
        pages: 16384
        })";
    std::string strFive_ = R"( result_file: "/data/local/tmp/)";
    std::string strSix_ = R"(.htrace"
        sample_duration: 5000
        })";
    std::string strNine_ = R"( plugin_configs {
        plugin_name: "ftrace-plugin"
        sample_interval: 1000
        config_data {
        ftrace_events: "sched/sched_switch"
        ftrace_events: "power/suspend_resume"
        ftrace_events: "sched/sched_wakeup"
        ftrace_events: "sched/sched_wakeup_new"
        ftrace_events: "sched/sched_waking"
        ftrace_events: "sched/sched_process_exit"
        ftrace_events: "sched/sched_process_free"
        ftrace_events: "task/task_newtask"
        ftrace_events: "task/task_rename"
        ftrace_events: "power/cpu_frequency"
        ftrace_events: "power/cpu_idle"
        hitrace_categories: "ace"
        hitrace_categories: "app"
        hitrace_categories: "ark"
        hitrace_categories: "graphic"
        hitrace_categories: "ohos"
        hitrace_categories: "bin)";
    std::string strEleven_ = R"(der"
        hitrace_categories: "irq"
        hitrace_categories: "pagecache"
        hitrace_categories: "zaudio"
        buffer_size_kb: 20480
        flush_interval_ms: 1000
        flush_threshold_kb: 4096
        parse_ksyms: true
        clock: "boot"
        trace_period_ms: 200
        debug_on: false
        hitrace_time: 5
        }
        })";
    std::string strSeven_ = R"( plugin_configs {
        plugin_name: "hiperf-plugin"
        sample_interval: 5000
        config_data {
        is_root: false
        outfile_name: "/data/local/tmp/)";
    std::string strEight_ = R"(.data"
        record_args: "-f 1000 -a  --cpu-limit 100 -e " SPUtils::GetProductName() "-cpu-cycles,sched:sched_waking )";
    std::string strTen_ = R"(--call-stack dwarf --clockid monotonic --offcpu -m 256"
        }
        })";
    std::string conFig_ = R"(CONFIG)";
};
}
}
#endif