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

#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include "securec.h"
#include "include/hitrace_converter.h"
#include "include/sp_log.h"
#include "include/common.h"
#include "include/sp_utils.h"

namespace OHOS {
namespace SmartPerf {
TraceFileParser::TraceFileParser(const std::string& filePath) : filePath_(filePath) {}

bool TraceFileParser::Parse()
{
    char outPutPathChar[PATH_MAX] = {0x00};
    if (realpath(filePath_.c_str(), outPutPathChar) == nullptr) {
        LOGE("data dir %s is nullptr", filePath_.c_str());
        return false;
    }
    fileStream_.open(outPutPathChar, std::ios::binary | std::ios::in);
    if (!fileStream_.is_open()) {
        errorMsg_ = "Failed to open file: " + filePath_;
        return false;
    }
    if (!ReadFileHeader()) {
        return false;
    }
    if (fileHeader_.magicNumber != MAGIC_NUMBER) {
        errorMsg_ = "Invalid magic number: expected 0x" + std::to_string(MAGIC_NUMBER);
        return false;
    }
    while (fileStream_.good() && !fileStream_.eof()) {
        if (!ReadContentSection()) {
            break;
        }
    }
    isValid_ = true;
    return true;
}

bool TraceFileParser::IsValid() const
{
    return isValid_;
}

const std::string& TraceFileParser::GetErrorMsg() const
{
    return errorMsg_;
}

const TraceFileHeader& TraceFileParser::GetFileHeader() const
{
    return fileHeader_;
}

const TraceMetadata& TraceFileParser::GetMetadata() const
{
    return metadata_;
}

const std::map<int, CpuTraceData>& TraceFileParser::GetCpuTraces() const
{
    return cpuTraces_;
}

const std::vector<uint8_t>& TraceFileParser::GetEventFormats() const
{
    return eventFormats_;
}

const std::vector<uint8_t>& TraceFileParser::GetBaseInfo() const
{
    LOGD("Uint8_t conversion function");
    return baseInfo_;
}

const std::vector<uint8_t>& TraceFileParser::GetCmdLines() const
{
    return cmdLines_;
}

const std::vector<uint8_t>& TraceFileParser::GetTgids() const
{
    return tgids_;
}

uint64_t TraceFileParser::GetTraceStartTime() const
{
    return traceStartTime_;
}

uint64_t TraceFileParser::GetTraceEndTime() const
{
    return traceEndTime_;
}

bool TraceFileParser::ReadFileHeader()
{
    fileStream_.read(reinterpret_cast<char*>(&fileHeader_), sizeof(TraceFileHeader));
    if (fileStream_.gcount() != sizeof(TraceFileHeader)) {
        errorMsg_ = "Failed to read file header";
        return false;
    }
    return true;
}

bool TraceFileParser::ReadContentSection()
{
    TraceFileContentHeader hdr = {};
    if (fileStream_.read(reinterpret_cast<char*>(&hdr), sizeof(hdr)).gcount() != sizeof(hdr)) {
        errorMsg_ = "Failed to read content header";
        return false;
    }
    std::vector<uint8_t> data;
    if (hdr.length > 0 && hdr.length <= MAX_CONTENT_LENGTH) {
        data.resize(hdr.length);
        if (fileStream_.read(reinterpret_cast<char*>(data.data()), hdr.length).gcount() != hdr.length) {
            errorMsg_ = "Failed to read content data, expected " + std::to_string(hdr.length) + " bytes";
            return false;
        }
    }
    switch (hdr.type) {
        case CONTENT_TYPE_BASE_INFO:
            ParseBaseInfo(data);
            break;
        case CONTENT_TYPE_EVENTS_FORMAT:
            eventFormats_ = std::move(data);
            break;
        case CONTENT_TYPE_CMDLINES:
            cmdLines_ = std::move(data);
            break;
        case CONTENT_TYPE_TGIDS:
            tgids_ = std::move(data);
            break;
        default:
            if (hdr.type >= CONTENT_TYPE_CPU_RAW) {
                int cpuId = hdr.type - CONTENT_TYPE_CPU_RAW;
                CpuTraceData cpuData;
                cpuData.cpuId = cpuId;
                cpuData.data = std::move(data);
                uint64_t firstTs = 0;
                uint64_t lastTs = 0;
                ParsePageTimestamps(cpuData.data, firstTs, lastTs);
                cpuData.firstTimestamp = firstTs;
                cpuData.lastTimestamp = lastTs;
                cpuTraces_[cpuId] = std::move(cpuData);
                if (traceStartTime_ == 0 || firstTs < traceStartTime_) {
                    traceStartTime_ = firstTs;
                }
                if (lastTs > traceEndTime_) {
                    traceEndTime_ = lastTs;
                }
            }
            break;
    }
    return true;
}

    void TraceFileParser::ParseBaseInfo(const std::vector<uint8_t>& data)
    {
        std::string content(data.begin(), data.end());
        size_t pos = 0;
        constexpr size_t kernelPrefixLen = 16;
        constexpr size_t unixPrefixLen = 14;
        constexpr size_t bootPrefixLen = 14;

        while (pos < content.size()) {
            size_t lineEnd = content.find('\n', pos);
            if (lineEnd == std::string::npos) {
                lineEnd = content.size();
            }
            std::string line = content.substr(pos, lineEnd - pos);
            if (line.find("KERNEL_VERSION:") == 0) {
                metadata_.kernelVersion = line.substr(kernelPrefixLen);
            } else if (line.find("UNIX_TIME_MS:") == 0) {
                std::string unixTimeMsLine = line.substr(unixPrefixLen);
                metadata_.unixTimeMs = SPUtilesTye::StringToSometype<uint64_t>(unixTimeMsLine);
            } else if (line.find("BOOT_TIME_MS:") == 0) {
                std::string bootTimeMsLine = line.substr(bootPrefixLen);
                metadata_.bootTimeMs = SPUtilesTye::StringToSometype<uint64_t>(bootTimeMsLine);
            }

            pos = lineEnd + 1;
        }
    }

bool TraceFileParser::ParsePageTimestamps(const std::vector<uint8_t>& data, uint64_t& firstTs, uint64_t& lastTs)
{
    firstTs = 0;
    lastTs = 0;

    size_t offset = 0;
    bool hasFirst = false;

    while (offset + sizeof(PageHeader) <= data.size()) {
        PageHeader pageHeader = {};
        if (memcpy_s(&pageHeader, sizeof(pageHeader), data.data() + offset, sizeof(PageHeader)) != EOK) {
            break;
        }

        if (pageHeader.size == 0 || pageHeader.size > PAGE_SIZE) {
            break;
        }

        if (!hasFirst || pageHeader.timestamp < firstTs) {
            firstTs = pageHeader.timestamp;
            hasFirst = true;
        }
        if (pageHeader.timestamp > lastTs) {
            lastTs = pageHeader.timestamp;
        }

        offset += PAGE_SIZE;
        if (offset >= data.size()) {
            break;
        }
    }

    return hasFirst;
}

TraceClipper::TraceClipper(std::shared_ptr<TraceFileParser> parser) : parser_(parser)
{
    if (parser_) {
        originalStartTime_ = parser_->GetTraceStartTime();
        originalEndTime_ = parser_->GetTraceEndTime();
    }
}

bool TraceClipper::ClipByTimeRange(uint64_t startTimeNs, uint64_t endTimeNs)
{
    if (!parser_ || !parser_->IsValid()) {
        errorMsg_ = "Parser is invalid";
        return false;
    }

    clippedStartTime_ = startTimeNs;
    clippedEndTime_ = endTimeNs;

    const auto& cpuTraces = parser_->GetCpuTraces();
    for (const auto& kv : cpuTraces) {
        int cpuId = kv.first;
        const CpuTraceData& cpuData = kv.second;

        std::vector<uint8_t> clippedData;
        if (!ClipCpuTraceData(cpuData, startTimeNs, endTimeNs, clippedData)) {
            continue;
        }

        if (!clippedData.empty()) {
            clippedCpuData_[cpuId] = std::move(clippedData);
        }
    }

    return true;
}

bool TraceClipper::SaveToFile(const std::string& outputPath)
{
    char outPutPathChar[PATH_MAX] = {0x00};
    if (realpath(outputPath.c_str(), outPutPathChar) == nullptr) {
        LOGE("data dir %s is nullptr", outputPath.c_str());
        return false;
    }
    std::ofstream outFile(outPutPathChar, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open()) {
        errorMsg_ = "Failed to create output file: " + outputPath;
        return false;
    }

    TraceFileHeader header = parser_->GetFileHeader();
    UpdateFileHeader(header);

    outFile.write(reinterpret_cast<const char*>(&header), sizeof(TraceFileHeader));

    auto writeContentSection = [&outFile](uint8_t type, const std::vector<uint8_t>& data) {
        TraceFileContentHeader contentHeader = {};
        contentHeader.type = type;
        contentHeader.length = static_cast<uint32_t>(data.size());
        outFile.write(reinterpret_cast<const char*>(&contentHeader), sizeof(TraceFileContentHeader));
        if (!data.empty()) {
            outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
        }
    };

    std::vector<uint8_t> baseInfoData = parser_->GetBaseInfo();
    writeContentSection(CONTENT_TYPE_BASE_INFO, baseInfoData);
    writeContentSection(CONTENT_TYPE_EVENTS_FORMAT, parser_->GetEventFormats());
    writeContentSection(CONTENT_TYPE_CMDLINES, parser_->GetCmdLines());
    writeContentSection(CONTENT_TYPE_TGIDS, parser_->GetTgids());

    for (const auto& kv : clippedCpuData_) {
        int cpuId = kv.first;
        const std::vector<uint8_t>& cpuData = kv.second;
        writeContentSection(CONTENT_TYPE_CPU_RAW + cpuId, cpuData);
    }

    outFile.close();
    return true;
}

uint64_t TraceClipper::GetOriginalStartTime() const
{
    return originalStartTime_;
}

uint64_t TraceClipper::GetOriginalEndTime() const
{
    return originalEndTime_;
}

uint64_t TraceClipper::GetClippedStartTime() const
{
    return clippedStartTime_;
}

uint64_t TraceClipper::GetClippedEndTime() const
{
    return clippedEndTime_;
}

const std::string& TraceClipper::GetErrorMsg() const
{
    return errorMsg_;
}

bool TraceClipper::ClipCpuTraceData(const CpuTraceData& cpuData, uint64_t startTimeNs,
                                    uint64_t endTimeNs, std::vector<uint8_t>& clippedData)
{
    const std::vector<uint8_t>& originalData = cpuData.data;
    size_t offset = 0;

    while (offset + sizeof(PageHeader) <= originalData.size()) {
        PageHeader pageHeader = {};
        if (memcpy_s(&pageHeader, sizeof(pageHeader), originalData.data() + offset, sizeof(PageHeader)) != EOK) {
            offset += PAGE_SIZE;
            if (offset >= originalData.size()) {
                break;
            }
            continue;
        }

        if (pageHeader.size == 0 || pageHeader.size > PAGE_SIZE) {
            offset += PAGE_SIZE;
            if (offset >= originalData.size()) {
                break;
            }
            continue;
        }

        if (pageHeader.timestamp >= startTimeNs && pageHeader.timestamp <= endTimeNs) {
            const uint8_t* pageStart = originalData.data() + offset;
            clippedData.insert(clippedData.end(), pageStart, pageStart + PAGE_SIZE);
        }

        offset += PAGE_SIZE;
        if (offset >= originalData.size()) {
            break;
        }
    }

    return true;
}

void TraceClipper::UpdateFileHeader(TraceFileHeader& header)
{
    size_t cpuCount = clippedCpuData_.size();
    header.reserved = (static_cast<uint64_t>(cpuCount) << 1) | (header.reserved & 1);
}

bool ConvertTraceByTime(const std::string& inputPath, const std::string& outputPath,
    uint64_t durationSec, std::string& errorMsg)
{
    auto parser = std::make_shared<TraceFileParser>(inputPath);
    if (!parser->Parse()) {
        errorMsg = parser->GetErrorMsg();
        return false;
    }

    uint64_t endTime = parser->GetTraceEndTime();
    uint64_t startTime = (endTime > durationSec * 1000000000)
                         ? (endTime - durationSec * 1000000000)
                         : parser->GetTraceStartTime();

    TraceClipper clipper(parser);
    if (!clipper.ClipByTimeRange(startTime, endTime)) {
        errorMsg = clipper.GetErrorMsg();
        return false;
    }

    if (!clipper.SaveToFile(outputPath)) {
        errorMsg = clipper.GetErrorMsg();
        return false;
    }

    return true;
}
}
}