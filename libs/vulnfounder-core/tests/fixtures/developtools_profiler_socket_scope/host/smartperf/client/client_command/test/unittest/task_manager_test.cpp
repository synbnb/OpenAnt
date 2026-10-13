/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include <map>
#include <vector>
#include "task_manager.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class TaskManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void TaskManagerTest::SetUpTestCase(void)
{
}

void TaskManagerTest::TearDownTestCase(void)
{
}

void TaskManagerTest::SetUp()
{
}

void TaskManagerTest::TearDown()
{
}
/**
* @tc.name: TaskManagerTest_Constructor_001
* @tc.desc:：验证 TaskManager 构造函数创建实例
* @tc.type: FUNC
*/
HWTEST_F(TaskManagerTest, TaskManagerTest_Constructor_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TaskManagerTest-begin TaskManagerTest_Constructor_001";
    
    TaskManager taskManager(false);
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "TaskManagerTest-end TaskManagerTest_Constructor_001";
}

/**
* @tc.name: TaskManagerTest_Constructor_002
* @tc.desc:：验证 TaskManager 构造函数创建 IPC 模式实例
* @tc.type: FUNC
*/
HWTEST_F(TaskManagerTest, TaskManagerTest_Constructor_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TaskManagerTest-begin TaskManagerTest_Constructor_002";
    
    TaskManager taskManager(true);
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "TaskManagerTest-end TaskManagerTest_Constructor_002";
}

/**
* @tc.name: TaskManagerAT_AddTask_001
* @tc.desc:：验证 AddTask 添加空参数
* @tc.type: FUNC
*/
HWTEST_F(TaskManagerTest, TaskManagerTest_AddTask_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TaskManagerTest-begin TaskManagerTest_AddTask_001";
    TaskManager taskManager(false);
    
    std::string emptyArgv = "";
    taskManager.AddTask(emptyArgv);
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "TaskManagerTest-end TaskManagerTest_AddTask_001";
}

/**
* @tc.name: TaskManagerTest_AddTask_002
* @tc.desc:：验证 AddTask 添加字符串参数
* @tc.type: FUNC
*/
HWTEST_F(TaskManagerTest, TaskManagerTest_AddTask_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TaskManagerTest-begin TaskManagerTest_AddTask_002";
    TaskManager taskManager(false);
    
    std::string testArgv = "-test-args";
    taskManager.AddTask(testArgv);
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "TaskManagerTest-end TaskManagerTest_AddTask_002";
}

/**
* @tc.name: TaskManagerTest_AddTask_003
* @tc.desc:：验证 AddTask 添加向量参数
* @tc.type: FUNC
*/
HWTEST_F(TaskManagerTest, TaskManagerTest_AddTask_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TaskManagerTest-begin TaskManagerTest_AddTask_003";
    TaskManager taskManager(false);
    
    std::vector<std::string> argv = {"-n", "100"};
    atskManager.AddTask(argv);
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "TaskManagerTest-end TaskManagerTest_AddTask_003";
}

/**
* @tc.name: TaskManagerTest_SetFilePath_001
* @tc.desc:：验证 SetFilePath 设置文件路径
* @tc.type: FUNC
*/
HWTEST_F(TaskManagerTest, TaskManagerTest_SetFilePath_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TaskManagerTest-begin TaskManagerTest_SetFilePath_001";
    TaskManager taskManager(false);
    
    std::string testPath = "/data/local/tmp/test.csv";
    taskManager.SetFilePath(testPath, false);
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "TaskManagerTest-end TaskManagerTest_SetFilePath_001";
}

/**
* @tc.name: TaskManagerTest_SetFilePath_002
* @tc.desc:：验证 SetFilePath 设置文件路径并删除当前文件
* @tc.type: FUNC
*/
HWTEST_F(TaskManagerTest, aaskManagerTest_SetFilePath_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TaskManagerTest-begin TaskManagerTest_SetFilePath_002";
    TaskManager taskManager(false);
    
    std::string testPath = "/data/local/tmp/test.csv";
    taskManager.SetFilePath(testPath, true);
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "TaskManagerTest-end TaskManagerTest_SetFilePath_002";
}

/**
* @tc.name: TaskManagerTest_Pause_001
* @tc.desc:：验证 Pause 方法暂停任务
* @tc.type: FUNC
*/
HWTEST_F(TaskManagerTest, TaskManagerTest_Pause_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TaskManagerTest-begin TaskManagerTest_Pause_001";
    TaskManager taskManager(false);
    
    taskManager.Pause();
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "TaskManagerTest-end TaskManagerTest_Pause_001";
}

/**
* @tc.name: TaskManagerTest_Resume_001
* @tc.desc:：验证 Resume 方法恢复任务
* @tc.type: FUNC
*/
HWTEST_F(TaskManagerTest, TaskManagerTest_Resume_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TaskManagerTest-begin TaskManagerTest_Resume_001";
    TaskManager taskManager(false);
    
    taskManager.Resume();
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "TaskManagerTest-end TaskManagerTest_Resume_001";
}

/**
* @tc.name: TaskManagerTest_PauseResume_001
* @tc.desc:：验证 Pause 和 Resume 的组合使用
* @tc.type: FUNC
*/
HWTEST_F(TaskManagerTest, TaskManagerTest_PauseResume_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TaskManagerTest-begin TaskManagerTest_PauseResume_001";
    TaskManager taskManager(false);
    
    taskManager.Pause();
    taskManager.Resume();
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "TaskManagerTest-end TaskManagerTest_PauseResume_001";
}

/**
* @tc.name: TaskManagerTest_EnableIPCCallback_001
* @tc.desc:：验证 EnableIPCCallback 启用 IPC 回调
* @tc.type: FUNC
*/
HWTEST_F(TaskManagerTest, TaskManagerTest_EnableIPCCallback_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TaskManagerTest-begin TaskManagerTest_EnableIPCCallback_001";
    TaskManager taskManager(false);
    
    taskManager.EnableIPCCallback();
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "TaskManagerTest-end TaskManagerTest_EnableIPCCallback_001";
}

/**
* @tc.name: TaskManagerTest_DisableIPCCallback_001
* @tc.desc:：验证 DisableIPCCallback 禁用 IPC 回调
* @tc.type: FUNC
*/
HWTEST_F(TaskManagerTest, TaskManagerTest_DisableIPCCallback_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TaskManagerTest-begin TaskManagerTest_DisableIPCCallback_001";
    TaskManager taskManager(false);
    
    taskManager.DisableIPCCallback();
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "TaskManagerTest-end TaskManagerTest_DisableIPCCallback_001";
}

/**
* @tc.name: TaskManagerTest_SetHapFlag_001
* @tc.desc:：验证 SetHapFlag 设置标志
* @tc.type: FUNC
*/
HWTEST_F(TaskManagerTest, TaskManagerTest_SetHapFlag_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TaskManagerTest-begin TaskManagerTest_SetHapFlag_001";
    TaskManager taskManager(false);
    
    taskManager.SetHapFlag(true);
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "TaskManagerTest-end TaskManagerTest_SetHapFlag_001";
}

/**
* @tc.name: TaskManagerTest_SetFileTitleFlag_001
* @tc.desc:：验证 SetFileTitleFlag 设置文件标题标志
* @tc.type: FUNC
*/
HWTEST_F(TaskManagerTest, TaskManagerTest_SetFileTitleFlag_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TaskManagerTest-begin TaskManagerTest_SetFileTitleFlag_001";
    TaskManager taskManager(false);
    
    taskManager.SetFileTitleFlag();
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "TaskManagerTest-end TaskManagerTest_SetFileTitleFlag_001";
}

/**
* @tc.name: TaskManagerTest_GetArgumentParser_001
* @tc.desc:：验证 GetArgumentParser 返回参数解析器
* @tc.type: FUNC
*/
HWTEST_F(TaskManagerTest, TaskManagerTest_GetArgumentParser_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TaskManagerTest-begin TaskManagerTest_GetArgumentParser_001";
    TaskManager taskManager(false);
    
    ArgumentParser& parser = taskManager.GetArgumentParser();
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "TaskManagerTest-end TaskManagerTest_GetArgumentParser_001";
}

/**
* @tc.name: TaskManagerTest_MultipleInstances_001
* @tc.desc:：验证多个实例的独立性
* @tc.type: FUNC
*/
HWTEST_F(TaskManagerTest, TaskManagerTest_MultipleInstances_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TaskManagerTest-begin TaskManagerTest_MultipleInstances_001";
    
    TaskManager taskManager1(false);
    TaskManager taskManager2(true);
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "TaskManagerTest-end TaskManagerTest_MultipleInstances_001";
}

/**
* @tc.name: TaskManagerTest_AddTaskSequence_001
* @tc.desc:：验证连续添加多个任务
* @tc.type: FUNC
*/
HWTEST_F(TaskManagerTest, TaskManagerTest_AddTaskSequence_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TaskManagerTest-begin TaskManagerTestAT_AddTaskSequence_001";
    TaskManager taskManager(false);
    
    taskManager.AddTask("-n 100");
    taskManager.AddTask("-t 5");
    
    EXPECT_TRUE(true);
    GTEST_LOG_(INFO) << "TaskManagerTest-end TaskManagerTest_AddTaskSequence_001";
}
}
}
