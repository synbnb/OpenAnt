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

#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <atomic>
#include <functional>
#include <future>
#include <queue>
#include <stdexcept>
#include <thread>

namespace OHOS::SmartPerf {
class ThreadPool {
public:
    ThreadPool() = delete;
    explicit ThreadPool(size_t);

    template <class FUN, class... ARGS>
    std::future<typename std::invoke_result<FUN, ARGS...>::type> PushTask(FUN&& f, ARGS&&... args)
    {
        using ret_type = typename std::invoke_result<FUN, ARGS...>::type;
        auto task = std::make_shared<std::packaged_task<ret_type()>>(
            std::bind(std::forward<FUN>(f), std::forward<ARGS>(args)...));

        auto res = task->get_future();
        {
            std::unique_lock<std::mutex> lock(mtx_);
            tasks_.emplace([task] { (*task)(); });
        }
        cond_.notify_one();
        return res;
    }
    ~ThreadPool();

    void Stop();

private:
    void Run();

private:
    std::vector<std::thread> ths_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mtx_;
    std::condition_variable cond_;
    std::atomic_bool stop_{false};
};
}

#endif  // THREAD_POOL_H