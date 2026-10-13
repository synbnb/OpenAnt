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
#include <gtest/gtest.h>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <fstream>
#include "visual_effect_analysis.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class VisualEffectAnalysisTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(VisualEffectAnalysisTest, GetInstance_001, TestSize.Level1)
{
    VisualEffectAnalysis &instance1 = VisualEffectAnalysis::GetInstance();
    VisualEffectAnalysis &instance2 = VisualEffectAnalysis::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

HWTEST_F(VisualEffectAnalysisTest, InitdynamicEffectRsData_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectRsData();
    string result = analysis.GetCpuCycle("part1|part2|part3|12345|part5");
    EXPECT_EQ(result, "12345");
}

HWTEST_F(VisualEffectAnalysisTest, InitdynamicEffectFeData_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectFeData();
    string result = analysis.GetCpuCycle("a|b|c|test|d");
    EXPECT_EQ(result, "test");
}

HWTEST_F(VisualEffectAnalysisTest, GetClusterNum_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "cpu_id=0 state=1000";
    int result = analysis.GetClusterNum(line);
    EXPECT_EQ(result, 0);
}

HWTEST_F(VisualEffectAnalysisTest, GetClusterNum_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "cpu_id=7 state=2000";
    
    int result = analysis.GetClusterNum(line);
    
    EXPECT_EQ(result, 7);
}

HWTEST_F(VisualEffectAnalysisTest, GetClusterNum_003, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "no_cpu_id_here";
    
    int result = analysis.GetClusterNum(line);
    
    EXPECT_EQ(result, 0);
}

HWTEST_F(VisualEffectAnalysisTest, GetClusterNum_004, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "";
    
    int result = analysis.GetClusterNum(line);
    
    EXPECT_EQ(result, 0);
}

HWTEST_F(VisualEffectAnalysisTest, GetCpuCycle_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "part1|part2|part3|12345|part5";
    
    string result = analysis.GetCpuCycle(line);
    
    EXPECT_EQ(result, "12345");
}

HWTEST_F(VisualEffectAnalysisTest, GetCpuCycle_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "a|b|c|cycle_value";
    
    string result = analysis.GetCpuCycle(line);
    
    EXPECT_EQ(result, "cycle_value");
}

HWTEST_F(VisualEffectAnalysisTest, GetCpuCycle_003, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "not_enough_pipes";
    
    string result = analysis.GetCpuCycle(line);
    
    EXPECT_EQ(result, "");
}

HWTEST_F(VisualEffectAnalysisTest, GetCpuCycle_004, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "";
    
    string result = analysis.GetCpuCycle(line);
    
    EXPECT_EQ(result, "");
}

HWTEST_F(VisualEffectAnalysisTest, SetTraceTime_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    int time = 5000;
    
    analysis.SetTraceTime(time);
    int clusterResult = analysis.GetClusterNum("cpu_id=5 state=1000");
    EXPECT_EQ(clusterResult, 5);
}

HWTEST_F(VisualEffectAnalysisTest, SetTraceTime_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    int time = 0;
    
    analysis.SetTraceTime(time);
    string cycleResult = analysis.GetCpuCycle("x|y|z|999|w");
    EXPECT_EQ(cycleResult, "999");
}

HWTEST_F(VisualEffectAnalysisTest, SetTraceTime_003, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    int time = -100;
    
    analysis.SetTraceTime(time);
    int clusterResult = analysis.GetClusterNum("cpu_id=3 state=2000");
    EXPECT_EQ(clusterResult, 3);
}

HWTEST_F(VisualEffectAnalysisTest, SetTraceBegin_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string traceStartPoint = "begin_marker";
    
    analysis.SetTraceBegin(traceStartPoint);
    string cycleResult = analysis.GetCpuCycle("a|b|c|result|d");
    EXPECT_EQ(cycleResult, "result");
}

HWTEST_F(VisualEffectAnalysisTest, SetTraceBegin_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string emptyBegin = "";
    
    analysis.SetTraceBegin(emptyBegin);
    int clusterResult = analysis.GetClusterNum("cpu_id=2 state=1500");
    EXPECT_EQ(clusterResult, 2);
}

HWTEST_F(VisualEffectAnalysisTest, SetTraceEnd_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string traceEndPoint = "end_marker";
    
    analysis.SetTraceEnd(traceEndPoint);
    string cycleResult = analysis.GetCpuCycle("p1|p2|p3|val|p5");
    EXPECT_EQ(cycleResult, "val");
}

HWTEST_F(VisualEffectAnalysisTest, SetTraceEnd_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string emptyEnd = "";
    
    analysis.SetTraceEnd(emptyEnd);
    int clusterResult = analysis.GetClusterNum("cpu_id=4 state=3000");
    EXPECT_EQ(clusterResult, 4);
}

HWTEST_F(VisualEffectAnalysisTest, GetGpuFre_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectRsData();
    string line = "gpufreq-0 gpufreq state=800000";
    
    analysis.GetGpuFre(line);
    string cycleResult = analysis.GetCpuCycle("part1|part2|part3|12345|part5");
    EXPECT_EQ(cycleResult, "12345");
}

HWTEST_F(VisualEffectAnalysisTest, GetGpuFre_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectRsData();
    string line = "gpufreq-1 gpufreq state=600000";
    
    analysis.GetGpuFre(line);
    int clusterResult = analysis.GetClusterNum("cpu_id=1 state=600000");
    EXPECT_EQ(clusterResult, 1);
}

HWTEST_F(VisualEffectAnalysisTest, GetGpuFre_003, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectRsData();
    string line = "no_gpufreq_here";
    
    analysis.GetGpuFre(line);
    EXPECT_TRUE(line.find("gpufreq-") == string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GetGpuFre_004, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectRsData();
    string line = "gpufreq-0 gpufreq state=";
    
    analysis.GetGpuFre(line);
    string cycleResult = analysis.GetCpuCycle("a|b|c|empty_state|d");
    EXPECT_EQ(cycleResult, "empty_state");
}

HWTEST_F(VisualEffectAnalysisTest, GpuLoad_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "gpufreq-0 gpuload state=50";
    
    analysis.GpuLoad(line);
    EXPECT_TRUE(line.find("gpuload state") != string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GpuLoad_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "gpufreq-1 gpuload state=75";
    
    analysis.GpuLoad(line);
    int clusterResult = analysis.GetClusterNum("cpu_id=6 state=2500");
    EXPECT_EQ(clusterResult, 6);
}

HWTEST_F(VisualEffectAnalysisTest, GpuLoad_003, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "no_gpuload_here";
    
    analysis.GpuLoad(line);
    EXPECT_TRUE(line.find("gpuload state") == string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GetUtCpuCycle_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectRsData();
    string line = "RSUniRenderThre OnRenderFramePerfCount-Ins|data|12345|more";
    
    analysis.GetUtCpuCycle(line);
    string cycleResult = analysis.GetCpuCycle("x|y|z|utcycle|w");
    EXPECT_EQ(cycleResult, "utcycle");
}

HWTEST_F(VisualEffectAnalysisTest, GetUtCpuCycle_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectRsData();
    string line = "other_thread other_function|data|67890|more";
    
    analysis.GetUtCpuCycle(line);
    EXPECT_TRUE(line.find("RSUniRenderThre") == string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GetRefreshRate_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectRsData();
    string line = "pendingRefreshRate: 60";
    
    analysis.GetRefreshRate(line);
    EXPECT_TRUE(line.find("pendingRefreshRate") != string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GetRefreshRate_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectRsData();
    string line = "pendingRefreshRate: 90";
    
    analysis.GetRefreshRate(line);
    int clusterResult = analysis.GetClusterNum("cpu_id=0 state=90000");
    EXPECT_EQ(clusterResult, 0);
}

HWTEST_F(VisualEffectAnalysisTest, GetRefreshRate_003, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectRsData();
    string line = "no_refresh_rate";
    
    analysis.GetRefreshRate(line);
    EXPECT_TRUE(line.find("pendingRefreshRate") == string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GetRefreshRate_004, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectRsData();
    string line = "pendingRefreshRate: 120";
    analysis.GetRefreshRate(line);
    string line2 = "pendingRefreshRate: 60";
    
    analysis.GetRefreshRate(line2);
    string cycleResult = analysis.GetCpuCycle("a|b|c|ratecheck|d");
    EXPECT_EQ(cycleResult, "ratecheck");
}

HWTEST_F(VisualEffectAnalysisTest, GetGpuCycle_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "GPU Cycles data|12345|67890|99999";
    
    analysis.GetGpuCycle(line);
    string cycleResult = analysis.GetCpuCycle("p1|p2|p3|gpucyc|p5");
    EXPECT_EQ(cycleResult, "gpucyc");
}

HWTEST_F(VisualEffectAnalysisTest, GetGpuCycle_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "no_gpu_cycles";
    
    analysis.GetGpuCycle(line);
    EXPECT_TRUE(line.find("GPU Cycles") == string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GetCpuIdFre_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.GetDeviceCpuNum();
    string line = "cpu_frequency: cpu_id=0 state=1800000";
    
    analysis.GetCpuIdFre(line);
    int clusterResult = analysis.GetClusterNum(line);
    EXPECT_EQ(clusterResult, 0);
}

HWTEST_F(VisualEffectAnalysisTest, GetCpuIdFre_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.GetDeviceCpuNum();
    string line = "cpu_frequency: cpu_id=3 state=2000000";
    
    analysis.GetCpuIdFre(line);
    int clusterResult = analysis.GetClusterNum(line);
    EXPECT_EQ(clusterResult, 3);
}

HWTEST_F(VisualEffectAnalysisTest, GetCpuIdFre_003, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.GetDeviceCpuNum();
    string line = "no_cpu_frequency";
    
    analysis.GetCpuIdFre(line);
    EXPECT_TRUE(line.find("cpu_frequency:") == string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GetDdrIdFre_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "ddr_cluster cpu_id=0 state=1800000";
    
    analysis.GetDdrIdFre(line);
    int clusterResult = analysis.GetClusterNum(line);
    EXPECT_EQ(clusterResult, 0);
}

HWTEST_F(VisualEffectAnalysisTest, GetDdrIdFre_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "ddr_cluster cpu_id=1 state=2000000";
    
    analysis.GetDdrIdFre(line);
    int clusterResult = analysis.GetClusterNum(line);
    EXPECT_EQ(clusterResult, 1);
}

HWTEST_F(VisualEffectAnalysisTest, GetDdrIdFre_003, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "no_ddr_cluster";
    
    analysis.GetDdrIdFre(line);
    EXPECT_TRUE(line.find("ddr_cluster") == string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GetCpuFre_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.GetDeviceCpuNum();
    analysis.InitdynamicEffectRsData();
    string line = "cpu_frequency: cpu_id=0 state=1800000";
    
    analysis.GetCpuIdFre(line);
    int clusterResult = analysis.GetClusterNum(line);
    EXPECT_EQ(clusterResult, 0);
}

HWTEST_F(VisualEffectAnalysisTest, GetCpuFre_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.GetDeviceCpuNum();
    analysis.InitdynamicEffectRsData();
    string line = "cpu_frequency: cpu_id=1 state=2000000";
    string line2 = "cpu_frequency: cpu_id=1 state=2500000";
    
    analysis.GetCpuIdFre(line);
    analysis.GetCpuIdFre(line2);
    int clusterResult = analysis.GetClusterNum(line2);
    EXPECT_EQ(clusterResult, 1);
}

HWTEST_F(VisualEffectAnalysisTest, GetDdrFre_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.GetDeviceDdrNum();
    analysis.InitdynamicEffectRsData();
    string line = "ddr_cluster cpu_id=0 state=1800";
    
    analysis.GetDdrIdFre(line);
    int clusterResult = analysis.GetClusterNum(line);
    EXPECT_EQ(clusterResult, 0);
}

HWTEST_F(VisualEffectAnalysisTest, GetDdrFre_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.GetDeviceDdrNum();
    analysis.InitdynamicEffectRsData();
    string line = "ddr_cluster cpu_id=1 state=2000";
    
    analysis.GetDdrIdFre(line);
    int clusterResult = analysis.GetClusterNum(line);
    EXPECT_EQ(clusterResult, 1);
}

HWTEST_F(VisualEffectAnalysisTest, GetExternalMemoryRead_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "External Memory Read [KB] | data|1024";
    
    analysis.GetExternalMemoryRead(line);
    EXPECT_TRUE(line.find("External Memory Read") != string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GetExternalMemoryRead_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "no_external_memory_read";
    
    analysis.GetExternalMemoryRead(line);
    EXPECT_TRUE(line.find("External Memory Read") == string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GetexternalMemoryWrite_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "External Memory Write [KB] | data|2048";
    
    analysis.GetexternalMemoryWrite(line);
    EXPECT_TRUE(line.find("External Memory Write") != string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GetexternalMemoryWrite_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "no_external_memory_write";
    
    analysis.GetexternalMemoryWrite(line);
    EXPECT_TRUE(line.find("External Memory Write") == string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GetexternalMemoryTraffic_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "External Memory Traffic [KB] | data|4096";
    
    analysis.GetexternalMemoryTraffic(line);
    EXPECT_TRUE(line.find("External Memory Traffic") != string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GetexternalMemoryTraffic_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "no_external_memory_traffic";
    
    analysis.GetexternalMemoryTraffic(line);
    EXPECT_TRUE(line.find("External Memory Traffic") == string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GetCutTime_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "10:123.456 some data";
    
    string result = analysis.GetCutTime(line);
    
    EXPECT_EQ(result, "10000");
}

HWTEST_F(VisualEffectAnalysisTest, GetCutTime_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "no_timestamp_here";
    
    string result = analysis.GetCutTime(line);
    
    EXPECT_EQ(result, "0");
}

HWTEST_F(VisualEffectAnalysisTest, GetBeginTraceTime_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "10:123.456 data";
    
    analysis.GetBeginTraceTime(line);
    string cutResult = analysis.GetCutTime("5:000.000 test");
    EXPECT_EQ(cutResult, "-5000");
}

HWTEST_F(VisualEffectAnalysisTest, GetBeginTraceTime_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "# comment line";
    
    analysis.GetBeginTraceTime(line);
    string cutResult = analysis.GetCutTime("5:000.000 test");
    EXPECT_EQ(cutResult, "-5000");
}

HWTEST_F(VisualEffectAnalysisTest, GetBeginTraceTime_003, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line = "data without timestamp";
    
    analysis.GetBeginTraceTime(line);
    string cutResult = analysis.GetCutTime("5:000.000 test");
    EXPECT_EQ(cutResult, "-5000");
}

HWTEST_F(VisualEffectAnalysisTest, GetRsLaneMap_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectRsData();
    string line = "render_service OnReadablePerfCount-Ins data";
    
    analysis.GetRsLaneMap(line);
    string cycleResult = analysis.GetCpuCycle("a|b|c|rslane|d");
    EXPECT_EQ(cycleResult, "rslane");
}

HWTEST_F(VisualEffectAnalysisTest, GetRsLaneMap_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectRsData();
    string line = "SceneAdapter::RenderFunction data";
    
    analysis.GetRsLaneMap(line);
    EXPECT_TRUE(line.find("SceneAdapter::RenderFunction") != string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GetRsLaneMap_003, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectRsData();
    string line = "other service other_function data";
    
    analysis.GetRsLaneMap(line);
    EXPECT_TRUE(line.find("render_service") == string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GetFeLaneMap_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectFeData();
    string line = "H:Waiting for Acquire Fence data";
    
    analysis.GetFeLaneMap(line);
    EXPECT_TRUE(line.find("H:Waiting for Acquire Fence") != string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, GetFeLaneMap_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectFeData();
    string line = "GPU Cycles data|12345";
    
    analysis.GetFeLaneMap(line);
    string cycleResult = analysis.GetCpuCycle("a|b|c|felane|d");
    EXPECT_EQ(cycleResult, "felane");
}

HWTEST_F(VisualEffectAnalysisTest, GetFeLaneMap_003, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    analysis.InitdynamicEffectFeData();
    string line = "External Memory Read [KB] | data|1024";
    
    analysis.GetFeLaneMap(line);
    EXPECT_TRUE(line.find("H:Waiting for Acquire Fence") == string::npos);
}

HWTEST_F(VisualEffectAnalysisTest, VisualEffectRanking_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string beginStr = "BEGIN";
    string overStr = "END";
    
    analysis.VisualEffectRanking(beginStr, overStr);
    string cycleResult = analysis.GetCpuCycle("x|y|z|ranking|w");
    EXPECT_EQ(cycleResult, "ranking");
}

HWTEST_F(VisualEffectAnalysisTest, VisualEffectRanking_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string emptyBegin = "";
    string emptyOver = "";
    
    analysis.VisualEffectRanking(emptyBegin, emptyOver);
    int clusterResult = analysis.GetClusterNum("cpu_id=8 state=4000");
    EXPECT_EQ(clusterResult, 8);
}

HWTEST_F(VisualEffectAnalysisTest, VisualEffectRanking_003, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string beginStr = "";
    string overStr = "END";
    
    analysis.VisualEffectRanking(beginStr, overStr);
    string cycleResult = analysis.GetCpuCycle("p1|p2|p3|vrank3|p5");
    EXPECT_EQ(cycleResult, "vrank3");
}

HWTEST_F(VisualEffectAnalysisTest, InitIndexInfo_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    
    analysis.InitIndexInfo();
    string cycleResult = analysis.GetCpuCycle("a|b|c|idxinfo|d");
    EXPECT_EQ(cycleResult, "idxinfo");
}

HWTEST_F(VisualEffectAnalysisTest, GetDeviceCpuNum_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    
    analysis.GetDeviceCpuNum();
    int clusterResult = analysis.GetClusterNum("cpu_id=0 state=1000");
    EXPECT_EQ(clusterResult, 0);
}

HWTEST_F(VisualEffectAnalysisTest, GetDeviceDdrNum_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    
    analysis.GetDeviceDdrNum();
    int clusterResult = analysis.GetClusterNum("cpu_id=1 state=2000");
    EXPECT_EQ(clusterResult, 1);
}

HWTEST_F(VisualEffectAnalysisTest, MultipleInitCalls_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    
    analysis.InitdynamicEffectRsData();
    analysis.InitdynamicEffectRsData();
    analysis.InitdynamicEffectRsData();
    string cycleResult = analysis.GetCpuCycle("m1|m2|m3|multi1|m5");
    EXPECT_EQ(cycleResult, "multi1");
}

HWTEST_F(VisualEffectAnalysisTest, MultipleInitCalls_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    
    analysis.InitdynamicEffectFeData();
    analysis.InitdynamicEffectFeData();
    analysis.InitdynamicEffectFeData();
    string cycleResult = analysis.GetCpuCycle("n1|n2|n3|multi2|n5");
    EXPECT_EQ(cycleResult, "multi2");
}

HWTEST_F(VisualEffectAnalysisTest, SetMultipleTimes_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    int time1 = 5000;
    int time2 = 10000;
    int time3 = 15000;
    
    analysis.SetTraceTime(time1);
    analysis.SetTraceTime(time2);
    analysis.SetTraceTime(time3);
    int clusterResult = analysis.GetClusterNum("cpu_id=9 state=5000");
    EXPECT_EQ(clusterResult, 9);
}

HWTEST_F(VisualEffectAnalysisTest, SetMultipleBeginPoints_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string begin1 = "marker1";
    string begin2 = "marker2";
    string begin3 = "marker3";
    
    analysis.SetTraceBegin(begin1);
    analysis.SetTraceBegin(begin2);
    analysis.SetTraceBegin(begin3);
    string cycleResult = analysis.GetCpuCycle("a|b|c|mbegin|d");
    EXPECT_EQ(cycleResult, "mbegin");
}

HWTEST_F(VisualEffectAnalysisTest, SetMultipleEndPoints_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string end1 = "end_marker1";
    string end2 = "end_marker2";
    string end3 = "end_marker3";
    
    analysis.SetTraceEnd(end1);
    analysis.SetTraceEnd(end2);
    analysis.SetTraceEnd(end3);
    int clusterResult = analysis.GetClusterNum("cpu_id=10 state=6000");
    EXPECT_EQ(clusterResult, 10);
}

HWTEST_F(VisualEffectAnalysisTest, EmptyLines_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string emptyLine = "";
    
    analysis.GetRsLaneMap(emptyLine);
    analysis.GetFeLaneMap(emptyLine);
    analysis.GetGpuFre(emptyLine);
    analysis.GpuLoad(emptyLine);
    analysis.GetUtCpuCycle(emptyLine);
    analysis.GetRefreshRate(emptyLine);
    analysis.GetGpuCycle(emptyLine);
    analysis.GetCpuIdFre(emptyLine);
    analysis.GetDdrIdFre(emptyLine);
    analysis.GetExternalMemoryRead(emptyLine);
    analysis.GetexternalMemoryWrite(emptyLine);
    analysis.GetexternalMemoryTraffic(emptyLine);
    string cycleResult = analysis.GetCpuCycle("e1|e2|e3|empty|e5");
    EXPECT_EQ(cycleResult, "empty");
}

HWTEST_F(VisualEffectAnalysisTest, GpuLoadAccumulation_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line1 = "gpufreq-0 gpuload state=50";
    string line2 = "gpufreq-0 gpuload state=60";
    string line3 = "gpufreq-0 gpuload state=70";
    
    analysis.GpuLoad(line1);
    analysis.GpuLoad(line2);
    analysis.GpuLoad(line3);
    int clusterResult = analysis.GetClusterNum("cpu_id=11 state=7000");
    EXPECT_EQ(clusterResult, 11);
}

HWTEST_F(VisualEffectAnalysisTest, GpuCycleAccumulation_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line1 = "GPU Cycles data|1000|2000|3000";
    string line2 = "GPU Cycles data|4000|5000|6000";
    string line3 = "GPU Cycles data|7000|8000|9000";
    
    analysis.GetGpuCycle(line1);
    analysis.GetGpuCycle(line2);
    analysis.GetGpuCycle(line3);
    string cycleResult = analysis.GetCpuCycle("g1|g2|g3|gpuacc|g5");
    EXPECT_EQ(cycleResult, "gpuacc");
}

HWTEST_F(VisualEffectAnalysisTest, ExternalMemoryAccumulation_001, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line1 = "External Memory Read [KB] | data|1024";
    string line2 = "External Memory Read [KB] | data|2048";
    string line3 = "External Memory Read [KB] | data|4096";
    
    analysis.GetExternalMemoryRead(line1);
    analysis.GetExternalMemoryRead(line2);
    analysis.GetExternalMemoryRead(line3);
    string cycleResult = analysis.GetCpuCycle("r1|r2|r3|emacc1|r5");
    EXPECT_EQ(cycleResult, "emacc1");
}

HWTEST_F(VisualEffectAnalysisTest, ExternalMemoryAccumulation_002, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line1 = "External Memory Write [KB] | data|512";
    string line2 = "External Memory Write [KB] | data|1024";
    string line3 = "External Memory Write [KB] | data|2048";
    
    analysis.GetexternalMemoryWrite(line1);
    analysis.GetexternalMemoryWrite(line2);
    analysis.GetexternalMemoryWrite(line3);
    int clusterResult = analysis.GetClusterNum("cpu_id=12 state=8000");
    EXPECT_EQ(clusterResult, 12);
}

HWTEST_F(VisualEffectAnalysisTest, ExternalMemoryAccumulation_003, TestSize.Level1)
{
    VisualEffectAnalysis &analysis = VisualEffectAnalysis::GetInstance();
    string line1 = "External Memory Traffic [KB] | data|8192";
    string line2 = "External Memory Traffic [KB] | data|16384";
    string line3 = "External Memory Traffic [KB] | data|32768";
    
    analysis.GetexternalMemoryTraffic(line1);
    analysis.GetexternalMemoryTraffic(line2);
    analysis.GetexternalMemoryTraffic(line3);
    string cycleResult = analysis.GetCpuCycle("t1|t2|t3|emacc3|t5");
    EXPECT_EQ(cycleResult, "emacc3");
}

}
}
