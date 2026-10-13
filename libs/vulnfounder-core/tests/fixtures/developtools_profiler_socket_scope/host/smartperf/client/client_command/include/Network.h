/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
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

#ifndef NETWORK_H
#define NETWORK_H
#include "sp_profiler.h"
#include <string>
namespace OHOS {
namespace SmartPerf {
class Network : public SpProfiler {
public:
    std::map<std::string, std::string> ItemData() override;
    static Network &GetInstance()
    {
        static Network instance;
        return instance;
    }
    std::map<std::string, std::string> GetNetworkInfo();
    void GetCurNetwork(long long &networkCurRx, long long &networkCurTx);
    void IsFindHap();
    void IsStopFindHap();
    void ThreadGetHapNetwork();
    void ClearHapFlag();
    void ThreadFunctions();
    std::map<std::string, std::string> GetNetworkInfoDev();
    bool PerciseMatch(const char *buff, const std::string &netStr);
private:
    Network() {};
    Network(const Network &);
    Network &operator = (const Network &);
    std::map<std::string, std::string> result = {};
    long long rmnetCurRx = 0;
    long long rmnetCurTx = 0;
    long long ethCurRx = 0;
    long long ethCurTx = 0;
    long long wlanCurRx = 0;
    long long wlanCurTx = 0;
    long long allTx = 0;
    long long allRx = 0;
    long long curTx = 0;
    long long curRx = 0;
    long long diffTx = 0;
    long long diffRx = 0;
    bool isFirst = true;
    bool hapFlag = false;
    bool stophapFlag = false;
};
}
}
#endif // NETWORK_H
