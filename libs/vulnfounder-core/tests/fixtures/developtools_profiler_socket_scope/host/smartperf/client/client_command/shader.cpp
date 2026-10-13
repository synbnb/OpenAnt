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
#include "include/shader.h"
#include "include/sp_utils.h"
#include "include/sp_log.h"
#include "include/common.h"
#include <fstream>
#include <sstream>
#include <regex>

namespace OHOS {
namespace SmartPerf {

void Shader::SetPkgName(const std::string& pkgName)
{
    pkgName_ = pkgName;
}

std::map<std::string, std::string> Shader::ItemData()
{
    std::string filePath = GetShaderReportPath();
    std::string content = ReadFileContent(filePath);
    ShaderMetrics metrics = ParseShaderMetrics(content);
    return FormatMetricsAsMap(metrics);
}

std::string Shader::GetShaderReportPath() const
{
    if (pkgName_.empty()) {
        return "";
    }
    return "/data/app/el1/100/system_optimize/" + pkgName_ + "/shader_cache/shader_dfx";
}

std::string Shader::ReadFileContent(const std::string& path)
{
    std::string cmdResult;
    if (path.empty()) {
        LOGE("Shader: Empty file path");
        return "";
    }
    std::string shaderFile = path + "/shader_report_info.txt";
    if (!SPUtils::FileAccess(shaderFile)) {
        LOGE("%s not be created!", shaderFile.c_str());
        return "";
    }
    std::string content;
    std::string line;
    size_t curSize = SPUtils::GetFileSize(shaderFile);
    if (curSize == lastSize_) {
        LOGD("The cur file do not change");
        return "";
    }
    char fileName[PATH_MAX] = {0x00};
    if (realpath(shaderFile.c_str(), fileName) == nullptr) {
        LOGE("the file not exeit");
        return "";
    }
    std::ifstream file(shaderFile, std::ios::in | std::ios::binary);
    if (!file) {
        LOGE("the file not exeit");
        return "";
    }
    file.seekg(lastSize_);
    while (std::getline(file, line)) {
        content = line;
    }
    lastSize_ = curSize;
    LOGD("Shader: Successfully read file: %s", path.c_str());
    return content;
}

ShaderMetrics Shader::ParseShaderMetrics(const std::string& content) const
{
    ShaderMetrics metrics;
    std::string keyCompileNum = "CompileNum: ";
    std::string keyCompileDuration = "CompileDuration: ";

    if (content.empty()) {
        LOGD("Shader: Empty content, returning default metrics");
        return metrics;
    }

    size_t posCompileNum = content.find(keyCompileNum);
    if (posCompileNum == std::string::npos) {
        LOGE("not find CompileNum");
        return metrics;
    }
    posCompileNum += keyCompileNum.length();
    size_t comPos = content.find(",", posCompileNum);
    if (comPos == std::string::npos) {
        LOGE("not find Separator");
        return metrics;
    }
    std::string compileNum = content.substr(posCompileNum, comPos - posCompileNum);
    metrics.compileNum = SPUtilesTye::StringToSometype<int>(compileNum);

    size_t posCompileDuration = content.find(keyCompileDuration, comPos);
    if (posCompileDuration == std::string::npos) {
        LOGE("not find CompileDuration");
        return metrics;
    }

    posCompileDuration += keyCompileDuration.length();
    size_t endPos = content.length();
    std::string compileDuration = content.substr(posCompileDuration, endPos - posCompileDuration);
    metrics.compileDuration = SPUtilesTye::StringToSometype<int>(compileDuration);
    return metrics;
}

std::map<std::string, std::string> Shader::FormatMetricsAsMap(const ShaderMetrics& metrics) const
{
    std::map<std::string, std::string> result;

    result["times"] = std::to_string(metrics.compileNum);
    result["duration"] = std::to_string(metrics.compileDuration);

    LOGD("Shader: Formatted metrics - compileNum=%s, compileDuration=%s",
         result["times"].c_str(), result["duration"].c_str());

    return result;
}

} // namespace SmartPerf
} // namespace OHOS