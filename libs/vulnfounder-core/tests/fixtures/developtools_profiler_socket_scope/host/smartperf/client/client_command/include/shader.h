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
#ifndef SHADER_H
#define SHADER_H
#include <string>
#include "sp_profiler.h"

namespace OHOS {
namespace SmartPerf {
struct ShaderMetrics {
    int compileNum = 0;
    int compileDuration = 0;
};

class Shader : public SpProfiler {
public:
    std::map<std::string, std::string> ItemData() override;
    static Shader& GetInstance()
    {
        static Shader instance;
        return instance;
    }
    void SetPkgName(const std::string& pkgName);

private:
    Shader() {};
    Shader(const Shader &) = delete;
    Shader &operator=(const Shader &) = delete;

    // Helper functions following Method Decomposition Rule
    std::string GetShaderReportPath() const;
    std::string ReadFileContent(const std::string& path);
    ShaderMetrics ParseShaderMetrics(const std::string& content) const;
    std::map<std::string, std::string> FormatMetricsAsMap(const ShaderMetrics& metrics) const;

    std::string pkgName_;
    size_t lastSize_ = 0;
};
}
}
#endif