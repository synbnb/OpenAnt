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
#include <iostream>
#include <sstream>
#include <thread>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "include/sp_utils.h"
#include "include/Capture.h"
#include "include/sp_log.h"
#include "display_manager.h"
#include "wm_common.h"
#include "png.h"
#include <filesystem>
#include "include/common.h"
namespace OHOS {
namespace SmartPerf {
using namespace OHOS::Media;
using namespace OHOS::Rosen;
std::map<std::string, std::string> Capture::ItemData()
{
    std::map<std::string, std::string> result;
    const int two = 2;
    const int modResult = callNum % two;
    callNum++;
    curTime = GetCurTimes();
    std::string screenCapPath = "data/local/tmp/capture/screenCap_" + std::to_string(curTime);
    std::string path = "NA";
    if (isSocketMessage) {
        if (modResult == 0) {
            path = screenCapPath + ".jpeg";
            result["capture"] = path;
            TriggerGetCatchSocket();
        }
    } else {
        if (modResult == 0) {
            path = screenCapPath + ".png";
            result["capture"] = path;
            TriggerGetCatch();
        }
    }
    result["capture"] = path;
    LOGI("Capture:ItemData map size(%u)", result.size());
    return result;
}

long long Capture::GetCurTimes()
{
    return SPUtils::GetCurTime();
}

void Capture::SocketMessage()
{
    isSocketMessage = true;
}
void Capture::ThreadGetCatch()
{
    const std::string captureDir = "/data/local/tmp/capture";
    const std::string savePath = captureDir + "/screenCap_" + std::to_string(curTime) + ".png";
    std::string cmdResult;
    if (!SPUtils::FileAccess(captureDir)) {
        std::string capturePath = CMD_COMMAND_MAP.at(CmdCommand::CREAT_DIR) + captureDir;
        if (!SPUtils::LoadCmd(capturePath, cmdResult)) {
            LOGE("%s capture not be created!", captureDir.c_str());
            return;
        } else {
            LOGD("%s created successfully!", captureDir.c_str());
        }
    };
    std::ostringstream errorRecv;
    auto fd = open(savePath.c_str(), O_RDWR | O_CREAT, 0666);
    if (fd == -1) {
        LOGE("Failed to open file: %s", savePath.c_str());
        return;
    }
    if (!TakeScreenCap(savePath)) {
        LOGE("Screen Capture Failed!");
        close(fd);
        return;
    }
    close(fd);
}


void Capture::ThreadGetCatchSocket()
{
    std::string captureTime = std::to_string(curTime);
    std::string captureDir = "/data/local/tmp/capture";
    std::string savePath = captureDir + "/screenCap_" + captureTime + ".jpeg";
    std::string cmdResult;
    if (!SPUtils::FileAccess(captureDir)) {
        std::string capturePath = CMD_COMMAND_MAP.at(CmdCommand::CREAT_DIR) + captureDir;
        if (!SPUtils::LoadCmd(capturePath, cmdResult)) {
            LOGE("%s capture not be created!", captureDir.c_str());
            return;
        } else {
            LOGD("%s created successfully!", captureDir.c_str());
        }
    };

    auto fd = open(savePath.c_str(), O_RDWR | O_CREAT, 0644);
    if (fd == -1) {
        LOGE("Capture::ThreadGetCatchSocket Failed to open file");
        return;
    }
    std::string snapshot = CMD_COMMAND_MAP.at(CmdCommand::SNAPSHOT);
    if (!SPUtils::LoadCmd(snapshot + savePath, cmdResult)) {
        LOGE("snapshot_display command failed!");
        close(fd);
        return;
    }
    close(fd);
}

void Capture::TriggerGetCatch()
{
    std::thread([this]() {
        this->ThreadGetCatch();
    }).detach();
}

void Capture::TriggerGetCatchSocket()
{
    std::thread([this]() {
        this->ThreadGetCatchSocket();
    }).detach();
}

bool Capture::TakeScreenCap(const std::string &savePath) const
{
    Rosen::DisplayManager &displayMgr = Rosen::DisplayManager::GetInstance();
    std::shared_ptr<Media::PixelMap> pixelMap = displayMgr.GetScreenshot(displayMgr.GetDefaultDisplayId());
    static constexpr int bitmapDepth = 8;
    if (pixelMap == nullptr) {
        LOGE("Failed to get display pixelMap");
        return false;
    }
    auto width = static_cast<uint32_t>(pixelMap->GetWidth());
    auto height = static_cast<uint32_t>(pixelMap->GetHeight());
    auto data = pixelMap->GetPixels();
    auto stride = static_cast<uint32_t>(pixelMap->GetRowBytes());
    png_structp pngStruct = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    if (pngStruct == nullptr) {
        LOGE("png_create_write_struct nullptr!");
        return false;
    }
    png_infop pngInfo = png_create_info_struct(pngStruct);
    if (pngInfo == nullptr) {
        LOGE("png_create_info_struct error nullptr!");
        png_destroy_write_struct(&pngStruct, nullptr);
        return false;
    }
    char realPath[PATH_MAX] = {0x00};
    if (realpath(savePath.c_str(), realPath) == nullptr) {
        std::cout << "" << std::endl;
    }
    FILE *fp = fopen(realPath, "wb");
    if (fp == nullptr) {
        LOGE("open file error!");
        png_destroy_write_struct(&pngStruct, &pngInfo);
        return false;
    }
    png_init_io(pngStruct, fp);
    png_set_IHDR(pngStruct, pngInfo, width, height, bitmapDepth, PNG_COLOR_TYPE_RGBA, PNG_INTERLACE_NONE,
        PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);
    png_set_packing(pngStruct);         // set packing info
    png_write_info(pngStruct, pngInfo); // write to header
    for (uint32_t i = 0; i < height; i++) {
        png_write_row(pngStruct, data + (i * stride));
    }
    png_write_end(pngStruct, pngInfo);
    // free
    png_destroy_write_struct(&pngStruct, &pngInfo);
    (void)fclose(fp);
    return true;
}
void Capture::SetCollectionNum()
{
    callNum = 0;
}
}
}
