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
#ifndef HITRACE_CONVERTER_H
#define HITRACE_CONVERTER_H
#include <cstdint>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace OHOS {
namespace SmartPerf {
constexpr int ALIGNMENT_COEFFICIENT = 4;
constexpr uint16_t MAGIC_NUMBER = 57161;
constexpr uint8_t FILE_RAW_TRACE = 0;
constexpr uint16_t VERSION_NUMBER = 1;
constexpr size_t PAGE_SIZE = 4096;
constexpr uint64_t MS_TO_NS = 1000000;
constexpr uint64_t S_TO_NS = 1000000000;
constexpr uint32_t MAX_CONTENT_LENGTH = 100 * 1024 * 1024;

enum ContentType : uint8_t {
    CONTENT_TYPE_DEFAULT = 0,
    CONTENT_TYPE_EVENTS_FORMAT = 1,
    CONTENT_TYPE_CMDLINES = 2,
    CONTENT_TYPE_TGIDS = 3,
    CONTENT_TYPE_CPU_RAW = 4,
    CONTENT_TYPE_HEADER_PAGE = 30,
    CONTENT_TYPE_PRINTK_FORMATS = 31,
    CONTENT_TYPE_KALLSYMS = 32,
    CONTENT_TYPE_BASE_INFO = 33
};

struct TraceFileHeader {
    uint16_t magicNumber;
    uint8_t fileType;
    uint16_t versionNumber;
    uint32_t reserved;
};

struct TraceFileContentHeader {
    uint8_t type;
    uint32_t length;
};

struct PageHeader {
    uint64_t timestamp;
    uint64_t size;
    uint8_t overwrite;
};

struct CpuTraceData {
    int cpuId;
    std::vector<uint8_t> data;
    uint64_t firstTimestamp = 0;
    uint64_t lastTimestamp = 0;
};

struct TraceMetadata {
    std::string kernelVersion;
    uint64_t unixTimeMs = 0;
    uint64_t bootTimeMs = 0;
};

class TraceFileParser {
public:
    explicit TraceFileParser(const std::string& filePath);
    bool Parse();
    bool IsValid() const;
    const std::string& GetErrorMsg() const;
    const TraceFileHeader& GetFileHeader() const;
    const TraceMetadata& GetMetadata() const;
    const std::map<int, CpuTraceData>& GetCpuTraces() const;
    const std::vector<uint8_t>& GetEventFormats() const;
    const std::vector<uint8_t>& GetBaseInfo() const;
    const std::vector<uint8_t>& GetCmdLines() const;
    const std::vector<uint8_t>& GetTgids() const;
    uint64_t GetTraceStartTime() const;
    uint64_t GetTraceEndTime() const;

private:
    bool ReadFileHeader();
    bool ReadContentSection();
    void ParseBaseInfo(const std::vector<uint8_t>& data);
    bool ParsePageTimestamps(const std::vector<uint8_t>& data, uint64_t& firstTs, uint64_t& lastTs);
    std::string filePath_;
    std::ifstream fileStream_;
    bool isValid_ = false;
    std::string errorMsg_;
    TraceFileHeader fileHeader_ = {};
    TraceMetadata metadata_ = {};
    std::map<int, CpuTraceData> cpuTraces_;
    std::vector<uint8_t> baseInfo_;
    std::vector<uint8_t> eventFormats_;
    std::vector<uint8_t> cmdLines_;
    std::vector<uint8_t> tgids_;
    uint64_t traceStartTime_ = 0;
    uint64_t traceEndTime_ = 0;
};

class TraceClipper {
public:
    explicit TraceClipper(std::shared_ptr<TraceFileParser> parser);
    bool ClipByTimeRange(uint64_t startTimeNs, uint64_t endTimeNs);
    bool SaveToFile(const std::string& outputPath);
    uint64_t GetOriginalStartTime() const;
    uint64_t GetOriginalEndTime() const;
    uint64_t GetClippedStartTime() const;
    uint64_t GetClippedEndTime() const;
    const std::string& GetErrorMsg() const;

private:
    bool ClipCpuTraceData(const CpuTraceData& cpuData, uint64_t startTimeNs,
                          uint64_t endTimeNs, std::vector<uint8_t>& clippedData);
    void UpdateFileHeader(TraceFileHeader& header);

    std::shared_ptr<TraceFileParser> parser_;
    std::string errorMsg_;
    uint64_t originalStartTime_ = 0;
    uint64_t originalEndTime_ = 0;
    uint64_t clippedStartTime_ = 0;
    uint64_t clippedEndTime_ = 0;
    std::map<int, std::vector<uint8_t>> clippedCpuData_;
};
}
}
#endif