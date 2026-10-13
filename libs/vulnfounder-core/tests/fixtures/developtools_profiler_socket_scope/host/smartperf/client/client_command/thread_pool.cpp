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

#include "thread_pool.h"
#include "iostream"
#include <string>

namespace OHOS::SmartPerf {
ThreadPool::ThreadPool(size_t threadNum)
{
    ths_.reserve(threadNum);
    for (size_t i = 0; i < threadNum; ++i) {
        ths_.emplace_back(std::thread(&ThreadPool::Run, this));
    }
}

ThreadPool::~ThreadPool()
{
    stop_.store(true);
    cond_.notify_all();
    for (auto& item : ths_) {
        if (item.joinable()) {
            item.join();
        }
    }
}

void ThreadPool::Stop()
{
    stop_.store(true);
    cond_.notify_all();
    for (auto& item : ths_) {
        if (item.joinable()) {
            item.join();
        }
    }
}

void ThreadPool::Run()
{
    while (!stop_) {
        std::function<void()> task = nullptr;
        {
            std::unique_lock<std::mutex> lock(mtx_);
            cond_.wait(lock, [this] { return stop_ || !this->tasks_.empty(); });
            if (stop_ || tasks_.empty()) {
                return;
            }
            task = std::move(tasks_.front());
            tasks_.pop();
        }
        if (task != nullptr) {
            task();
        }
    }
}
}