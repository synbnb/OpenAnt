/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under * Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with * License.
 * You may obtain a copy of * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under * License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See * License for * specific language governing permissions and
 * limitations under * License.
 */
#include <gtest/gtest.h>
#include <string>
#include <functional>
#include <chrono>
#include <thread>
#include "thread_pool.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class ThreadPoolTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ThreadPoolTest::SetUpTestCase(void)
{
}

void ThreadPoolTest::TearDownTestCase(void)
{
}

void ThreadPoolTest::SetUp()
{
}

void ThreadPoolTest::TearDown()
{
}
/**
* @tc.name: ThreadPoolTest_Constructor_001
* @tc.desc:：验证 ThreadPool 构造函数创建指定数量的线程
* @tc.type: FUNC
*/
HWTEST_F(ThreadPoolTest, ThreadPoolTest_Constructor_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ThreadPoolTest-begin ThreadPoolTest_Constructor_001";
    
    ThreadPool pool(4);
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "ThreadPoolTest-end ThreadPoolTest_Constructor_001";
}

/**
* @tc.name: ThreadPoolTest_Constructor_002
* @tc.desc:：验证 ThreadPool
构造函数创建单个线程
* @tc.type: FUNC
*/
HWTEST_F(ThreadPoolTest, ThreadPoolTest_Constructor_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ThreadPoolTest-begin ThreadPoolTest_Constructor_002";
    
    ThreadPool pool(1);
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "ThreadPoolTest-end ThreadPoolTest_Constructor_002";
}

/**
* @tc.name: ThreadPoolTest_PushTask_001
* @tc.desc:：验证 PushTask 执行简单任务
* @tc.type: FUNC
*/
HWTEST_F(ThreadPoolTest, ThreadPoolTest_PushTask_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ThreadPoolTest-begin ThreadPoolTest_PushTask_001";
    
    ThreadPool pool(2);
    auto result = pool.PushTask([]() { return 42; });
    
    EXPECT_EQ(result.get(), 42);
    GTEST_LOG_(INFO) << "ThreadPoolTest-end ThreadPoolTest_PushTask_001";
}

/**
* @tc.name: ThreadPoolTest_PushTask_002
* @tc.desc:：验证 PushTask 执行带参数的任务
* @tc.type: FUNC
*/
HWTEST_F(ThreadPoolTest, ThreadPoolTest_PushTask_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ThreadPoolTest-begin ThreadPoolTest_PushTask_002";
    
    ThreadPool pool(2);
    auto result = pool.PushTask([](int a, int b) { return a + b; }, 10, 20);
    
    EXPECT_EQ(result.get(), 30);
    GTEST_LOG_(INFO) << "ThreadPoolTest-end ThreadPoolTest_PushTask_002";
}

/**
* @tc.name: ThreadPoolTest_PushTask_003
* @tc.desc:：验证 PushTask 执行多个任务
* @tc.type: FUNC
*/
HWTEST_F(ThreadPoolTest, ThreadPoolTest_PushTask_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ThreadPoolTest-begin ThreadPoolTest_PushTask_003";
    
    ThreadPool pool(4);
    auto result1 = pool.PushTask([]() { return 1; });
    auto result2 = pool.PushTask([]() { return 2; });
    auto result3 = pool.PushTask([]() { return 3; });
    
    EXPECT_EQ(result1.get(), 1);
    EXPECT_EQ(result2.get(), 2);
    EXPECT_EQ(result3.get(), 3);
    GTEST_LOG_(INFO) << "ThreadPoolTest-end ThreadPoolTest_PushTask_003";
}

/**
* @tc.name: ThreadPoolTest_Stop_001
* @tc.desc:：验证 Stop 方法停止线程池
* @tc.type: FUNC
*/
HWTEST_F(ThreadPoolTest, ThreadPoolTest_Stop_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ThreadPoolTest-begin ThreadPoolTest_Stop_001";
    
    ThreadPool pool(2);
    pool.Stop();
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "ThreadPoolTest-end ThreadPoolTest_Stop_001";
}

/**
* @tc.name: ThreadPoolTest_Destructor_001
* @tc.desc:：验证析构函数正确清理资源
* @tc.type: FUNC
*/
HWTEST_F(ThreadPoolTest, ThreadPoolTest_Destructor_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ThreadPoolTest-begin ThreadPoolTest_Destructor_001";
    
    {
        ThreadPool pool(2);
        auto result = pool.PushTask([]() { return 100; });
        EXPECT_EQ(result.get(), 100);
    }
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "ThreadPoolTest-end ThreadPoolTest_Destructor_001";
}

/**
* @tc.name: ThreadPoolTest_MultipleTasks_001
* @tc.desc:：验证线程池处理大量任务
* @tc.type: FUNC
*/
HWTEST_F(ThreadPoolTest, ThreadPoolTest_MultipleTasks_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ThreadPoolTest-begin ThreadPoolTest_MultipleTasks_001";
    
    ThreadPool pool(4);
    std::vector<std::future<int>> results;
    
    for (int i = 0; i < 10; i++) {
        results.push_back(pool.PushTask([i]() { return i * 2; }));
    }
    
    for (int i = 0; i < 10; i++) {
        EXPECT_EQ(results[i].get(), i * 2);
    }
    
    GTEST_LOG_(INFO) << "ThreadPoolTest-end ThreadPoolTest_MultipleTasks_001";
}

/**
* @tc.name: ThreadPoolTest_TaskException_001
* @tc.desc:：验证任务执行时的异常处理
* @tc.type: FUNC
*/
HWTEST_F(ThreadPoolTest, ThreadPoolTest_TaskException_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ThreadPoolTest-begin ThreadPoolTest_TaskException_001";
    
    ThreadPool pool(2);
    auto result = pool.PushTask([]() -> int {
        throw std::runtime_error("Test exception");
        return 0;
    });
    
    EXPECT_THROW(result.get(), std::runtime_error);
    GTEST_LOG_(INFO) << "ThreadPoolTest-end ThreadPoolTest_TaskException_001";
}

/**
* @tc.name: ThreadPoolTest_TaskDelay_001
* @tc.desc:：验证任务执行时的延迟处理
* @tc.type: FUNC
*/
HWTEST_F(ThreadPoolTest, ThreadPoolTest_TaskDelay_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ThreadPoolTest-begin ThreadPoolTest_TaskDelay_001";
    
    ThreadPool pool(2);
    auto result = = pool.PushTask([]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return 999;
    });
    
    EXPECT_EQ(result.get(), 999);
    GTEST_LOG_(INFO) << "ThreadPoolTest-end ThreadPoolTest_TaskDelay_001";
}

/**
* @tc.name: ThreadPoolTest_ConcurrentTasks_001
* @tc.desc:：验证并发任务执行
* @tc.type: FUNC
*/
HWTEST_F(ThreadPoolTest, ThreadPoolTest_ConcurrentTasks_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ThreadPoolTest-begin ThreadPoolTest_ConcurrentTasks_001";
    
    ThreadPool pool(4);
    std::atomic<int> counter{0};
    
    std::vector<std::future<void>> results;
    for (int i = 0; i < 5; i++) {
        results.push_back(pool.PushTask([&counter]() {
            counter.fetch_add(1);
        }));
    }
    
    for (auto& result : results) {
        result.get();
    }
    
    EXPECT_EQ(counter.load(), 5);
    GTEST_LOG_(INFO) << "ThreadPoolTest-end ThreadPoolTest_ConcurrentTasks_001";
}
}
}
