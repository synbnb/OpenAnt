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

#ifndef HEARTBEAT_H
#define HEARTBEAT_H
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
namespace OHOS {
namespace SmartPerf {
class Heartbeat {
public:
    void HeartbeatRule();
    void UpdatestartTime();
    void KillSpId();
    static Heartbeat &GetInstance()
    {
        static Heartbeat instance;
        return instance;
    }

private:
    Heartbeat() {};
    Heartbeat(const Heartbeat &);
    Heartbeat &operator = (const Heartbeat &);
private:
    std::atomic<bool> isrunning = true;
    const int timeout = 1800;
    const int checkMessageTime = 300;
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point updateStart;
    std::mutex mtx;
};
}
}
#endif
