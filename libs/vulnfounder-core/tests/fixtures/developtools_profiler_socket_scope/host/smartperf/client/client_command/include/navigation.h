/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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

#ifndef NAVIGATION_H
#define NAVIGATION_H
#include <vector>
#include <string>
#include "sp_profiler.h"
namespace OHOS {
namespace SmartPerf {
class Navigation : public SpProfiler {
public:
    std::map<std::string, std::string> ItemData() override;
    static Navigation &GetInstance()
    {
        static Navigation instance;
        return instance;
    }
    std::map<std::string, std::string> GetNavInfo() const;
    void SetPackageName(const std::string &pName);
    std::string GetWinId(std::string navPid) const;
    std::map<std::string, std::string> GetNavResult(const std::string& winId) const;
    void SetProcessId(const std::string &pid);
    void SubstrNavName(const std::string &line, std::string &nameStr) const;
private:
    Navigation() {};
    Navigation(const Navigation &);
    Navigation &operator = (const Navigation &);
    std::string packageName = "";
    const int paramTwo = 2;
    const int paramThree = 3;
    std::string processId = "";
};
}
}
#endif // NAVIGATION_H
