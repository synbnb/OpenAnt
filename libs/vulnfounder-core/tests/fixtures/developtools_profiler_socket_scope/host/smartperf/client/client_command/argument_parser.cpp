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

#include "argument_parser.h"
#include <iomanip>
#include <cstring>
#include <sstream>
#include <vector>
#include <memory>
#include <cstring>
#include "securec.h"
#include "sp_utils.h"

namespace OHOS::SmartPerf {
namespace {
constexpr int LINE_W = 20;
}

void ArgumentParser::AddArgument(const std::string& name, ArgumentSpec info)
{
    if (specs_.count(name)) {
        errors_.push_back("Duplicate argument registered: " + name);
        return;
    }

    if ((info.type == ArgType::STRING || info.type == ArgType::BOOL) && (info.min || info.max)) {
        errors_.push_back("Only INT type supports min/max: " + name);
        return;
    }

    specs_[name] = info;
}

void ArgumentParser::Parse(const std::string& input)
{
    std::istringstream iss(input);
    std::vector<std::string> tokens;
    std::string token;

    while (iss >> std::quoted(token)) {
        tokens.push_back(token);
    }

    std::vector<std::unique_ptr<char[]>> storage;
    std::vector<char*> argv;
    for (auto& tok : tokens) {
        size_t tokLength = tok.size() + 1;
        storage.emplace_back(std::make_unique<char[]>(tokLength));
        if (strcpy_s(storage.back().get(), tokLength, tok.c_str()) != EOK) {
            return;
        }
        argv.push_back(storage.back().get());
    }

    int argc = static_cast<int>(argv.size());
    Parse(argc, argv.data());
}

void ArgumentParser::HandleIntParameter(const std::string& key, std::string value, const ArgumentSpec& spec)
{
    if (spec.type == ArgType::INT) {
        int val = SPUtilesTye::StringToSometype<int>(value);
        if (spec.min && val < *spec.min) {
            errors_.push_back("Value for " + key + " below min: " + std::to_string(*spec.min));
            return;
        }
        if (spec.max && val > *spec.max) {
            errors_.push_back("Value for " + key + " above max: " + std::to_string(*spec.max));
            return;
        }
        values_[key] = val;
    } else {
        values_[key] = value;
    }
}

void ArgumentParser::Parse(int argc, char* argv[])
{
    std::set<std::string> seen_args;
    for (int i = 1; i < argc; ++i) {
        std::string key = argv[i];
        if (key == "--help") {
            helpMode_ = true;
            return;
        }
        if (!specs_.count(key)) {
            errors_.push_back("Unknown argument: " + key);
            continue;
        }
        if (seen_args.count(key)) {
            errors_.push_back("Duplicate argument: " + key);
            const auto& spec = specs_[key];
            if (spec.type != ArgType::BOOL && i + 1 < argc && specs_.count(argv[i + 1]) == 0) {
                ++i;
            }
            continue;
        }
        seen_args.insert(key);
        const auto& spec = specs_[key];
        if (spec.type == ArgType::BOOL) {
            values_[key] = true;
            continue;
        }
        if (i + 1 >= argc || specs_.count(argv[i + 1])) {
            errors_.push_back("Missing value for argument: " + key);
            continue;
        }
        HandleIntParameter(key, std::string(argv[++i]), spec);
    }
}

std::optional<ArgumentParser::ArgValue> ArgumentParser::Get(const std::string& name) const
{
    auto it = values_.find(name);
    return it != values_.end() ? std::optional<ArgValue>(it->second) : std::nullopt;
}

void ArgumentParser::PrintHelp() const
{
    std::cout << "Available arguments:\n";
    for (const auto& [k, v] : specs_) {
        std::cout << "  " << std::left << std::setw(LINE_W) << k;

        switch (v.type) {
            case ArgType::STRING: std::cout << std::right << "(string) - "; break;
            case ArgType::INT:
                std::cout << "(int";
                if (v.min) std::cout << ", min=" << *v.min;
                if (v.max) std::cout << ", max=" << *v.max;
                std::cout << ") - ";
                break;
            case ArgType::BOOL: break;
        }

        if (!v.description.empty())
            std::cout  << v.description;

        std::cout << "\n";
    }
}

const std::unordered_map<std::string, ArgumentParser::ArgValue>& ArgumentParser::Values() const
{
    return values_;
}

const std::vector<std::string>& ArgumentParser::Errors() const
{
    return errors_;
}

bool ArgumentParser::Ok() const
{
    return errors_.empty();
}

bool ArgumentParser::IsHelpMode() const
{
    return helpMode_;
}

void ArgumentParser::SetValue(const std::string& key, const ArgValue& value)
{
    values_[key] = value;
}
}