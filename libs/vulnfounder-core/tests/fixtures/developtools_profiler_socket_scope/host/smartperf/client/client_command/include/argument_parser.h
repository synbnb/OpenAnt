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

#ifndef ARGUMENT_PARSER
#define ARGUMENT_PARSER

#include <iostream>
#include <string>
#include <unordered_map>
#include <map>
#include <variant>
#include <optional>
#include <vector>
#include <set>

namespace OHOS::SmartPerf {
class ArgumentParser {
public:
    using ArgValue = std::variant<int, std::string, bool>;
    enum class ArgType { INT, STRING, BOOL };
    struct ArgumentSpec {
        ArgType type;
        std::string description;
        std::optional<int> min;
        std::optional<int> max;
    };
    
    void AddArgument(const std::string& name, ArgumentSpec info);
    void Parse(int argc, char* argv[]);
    void Parse(const std::string& input);
    std::optional<ArgValue> Get(const std::string& name) const;
    void PrintHelp() const;
    const std::unordered_map<std::string, ArgValue>& Values() const;
    const std::vector<std::string>& Errors() const;
    bool Ok() const;
    bool IsHelpMode() const;
    void SetValue(const std::string& key, const ArgValue& value);

private:
    void HandleIntParameter(const std::string& key, std::string value, const ArgumentSpec& spec);

    std::unordered_map<std::string, ArgumentSpec> specs_ = {
        {"-N", {ArgumentParser::ArgType::INT,
            "set the collection times(default value is 0) range[1,2147483647], for example: -N 10", 1, 2147483647}
        },
        {"-PKG", {ArgumentParser::ArgType::STRING, "set package name, must add, for example: -PKG ohos.samples.ecg"}},
        {"-PID", {ArgumentParser::ArgType::INT, "set process pid, must add, for example: -PID 3568"}},
        {"-threads", {ArgumentParser::ArgType::BOOL,
            "get threads, must add -PID or -PKG, for example: -threads -PID 3568 or -threads -PKG ohos.samples.ecg"}
        },
        {"-fds", {ArgumentParser::ArgType::BOOL,
            "get file descriptor, must add -PID or -PKG, for example: -fds -PID 3568 or -fds -PKG ohos.samples.ecg"}
        },
        {"-c", {ArgumentParser::ArgType::BOOL,
            "get device CPU frequency and CPU usage, process CPU usage and CPU load"}},
        {"-g", {ArgumentParser::ArgType::BOOL, "get device GPU frequency and GPU load"}},
        {"-f", {ArgumentParser::ArgType::BOOL,
            "get app refresh fps(frames per second), fps jitters, and refresh rate"}},
        {"-profilerfps", {ArgumentParser::ArgType::BOOL, "get refresh fps and timestamp"}},
        {"-t", {ArgumentParser::ArgType::BOOL, "get remaining battery power and temperature"}},
        {"-p", {ArgumentParser::ArgType::BOOL,
            "get battery power consumption and voltage (Not supported by some devices)"}
        },
        {"-print", {ArgumentParser::ArgType::BOOL, "start mode print log"}},
        {"-r", {ArgumentParser::ArgType::BOOL, "get process memory and total memory"}},
        {"-snapshot", {ArgumentParser::ArgType::BOOL, "get screen capture"}},
        {"-net", {ArgumentParser::ArgType::BOOL, "get uplink and downlink traffic"}},
        {"-start", {ArgumentParser::ArgType::BOOL, "collection start command"}},
        {"-stop", {ArgumentParser::ArgType::BOOL, "collection stop command"}},
        {"-VIEW", {ArgumentParser::ArgType::STRING, "set layler, for example: -VIEW DisplayNode"}},
        {"-OUT", {ArgumentParser::ArgType::STRING, "set csv output path"}},
        {"-d", {ArgumentParser::ArgType::BOOL, "get device DDR information"}},
        {"-screen", {ArgumentParser::ArgType::BOOL, "get screen resolution"}},
        {"-deviceinfo", {ArgumentParser::ArgType::BOOL, "get device information"}},
        {"-ohtestfps", {ArgumentParser::ArgType::BOOL,
            "used by the vilidator to obtain the fps, the collection times can be set"}
        },
        {"-editorServer", {ArgumentParser::ArgType::BOOL,
            "start a process to listen to the socket message of the editor"}},
        {"-deviceServer", {ArgumentParser::ArgType::BOOL,
            "start a process to listen to the socket message of the device"}},
        {"-recordcapacity", {ArgumentParser::ArgType::BOOL, "get the battery level difference"}},
        {"--version", {ArgumentParser::ArgType::BOOL, "get version"}},
        {"--help", {ArgumentParser::ArgType::BOOL, "get help"}},
        {"responseTime", {ArgumentParser::ArgType::BOOL,
            "get the page response delay after an application is operated"}},
        {"completeTime", {ArgumentParser::ArgType::BOOL,
            "get the page completion delay after an application is operated"}},
        {"fpsohtest", {ArgumentParser::ArgType::BOOL, "used by the vilidator to obtain the fps"}},
        {"-gc", {ArgumentParser::ArgType::BOOL, "get gpu counter default frequency is 50"}},
        {"-GPU_COUNTER", {ArgumentParser::ArgType::INT,
            std::string("get gpu counter frequency which can be set in range [50,1000] and ") +
            "must be a factor of 50, for example: -GPU_COUNTER 250",
            50, 1000}
        },
        {"-ge", {ArgumentParser::ArgType::BOOL, "get game event"}},
        {"-fc", {ArgumentParser::ArgType::BOOL, "get caton info"}},
        {"-server", {ArgumentParser::ArgType::BOOL, "server"}},
        {"-o", {ArgumentParser::ArgType::BOOL, "sdk data recv"}},
        {"-ci", {ArgumentParser::ArgType::BOOL, "get cpu instructions and cycles"}},
        {"-fl", {ArgumentParser::ArgType::INT, "set fps"}},
        {"-ftl", {ArgumentParser::ArgType::INT, "set frameTime"}},
        {"-lockfreq", {ArgumentParser::ArgType::BOOL}},
        {"-nav", {ArgumentParser::ArgType::BOOL, "get page navigation information"}},
        {"-SESSIONID", {ArgumentParser::ArgType::STRING, "session id"}},
        {"-aischedule", {ArgumentParser::ArgType::BOOL, "AI schedule"}},
        {"-sh", {ArgumentParser::ArgType::BOOL, "shader"}},
        {"-ved", {ArgumentParser::ArgType::BOOL, "VisualEffectDisPatch"}},

        // UDP
        {"-CPU", {ArgumentParser::ArgType::BOOL}},
        {"-GPU", {ArgumentParser::ArgType::BOOL}},
        {"-FPS", {ArgumentParser::ArgType::BOOL}},
        {"-LOW_POWER", {ArgumentParser::ArgType::BOOL}},
        {"-FDS", {ArgumentParser::ArgType::BOOL}},
        {"-TEMP", {ArgumentParser::ArgType::BOOL}},
        {"-POWER", {ArgumentParser::ArgType::BOOL}},
        {"-RAM", {ArgumentParser::ArgType::BOOL}},
        {"-SCREEN", {ArgumentParser::ArgType::BOOL}},
        {"-DDR", {ArgumentParser::ArgType::BOOL}},
        {"-NET", {ArgumentParser::ArgType::BOOL}},
        {"-HCI", {ArgumentParser::ArgType::BOOL}},
        {"-TRACE", {ArgumentParser::ArgType::BOOL}},
        {"-j", {ArgumentParser::ArgType::BOOL}},
    };
    std::unordered_map<std::string, ArgValue> values_;
    std::vector<std::string> errors_;
    bool helpMode_{false};
};
}

#endif // ARGUMENT_PARSER