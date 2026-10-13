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
#ifndef OHOS_SP_LOG_H
#define OHOS_SP_LOG_H
#include <string>
namespace OHOS {
namespace SmartPerf {
const std::string LOG_FILE_DIR = "/data/local/tmp/spdaemonlog/";
typedef enum {
    SP_LOG_DEBUG,
    SP_LOG_INFO,
    SP_LOG_WARN,
    SP_LOG_ERROR,
} SpLogLevel;

void SpLog(SpLogLevel logLevel, bool isWriteLog, const char *fmt, ...);

#define LOGD(fmt, ...) \
    SpLog(SP_LOG_DEBUG, false, (std::string("[") + "SP_daemon" + "][" + __FUNCTION__ + "]:" + fmt).c_str(), \
        ##__VA_ARGS__)

#define LOGI(fmt, ...) \
    SpLog(SP_LOG_INFO, false, (std::string("[") + "SP_daemon" + "][" + __FUNCTION__ + "]:" + fmt).c_str(), \
        ##__VA_ARGS__)

#define LOGW(fmt, ...) \
    SpLog(SP_LOG_WARN, false, (std::string("[") + "SP_daemon" + "][" + __FUNCTION__ + "]:" + fmt).c_str(), \
        ##__VA_ARGS__)

#define LOGE(fmt, ...) \
    SpLog(SP_LOG_ERROR, false, (std::string("[") + "SP_daemon" + "][" + __FUNCTION__ + "]:" + fmt).c_str(), \
        ##__VA_ARGS__)

#define WLOGD(fmt, ...) \
    SpLog(SP_LOG_DEBUG, true, (std::string("[Debug][") + "SP_daemon" + "][" + __FUNCTION__ + "]:" + fmt).c_str(), \
        ##__VA_ARGS__)

#define WLOGI(fmt, ...) \
    SpLog(SP_LOG_INFO, true, (std::string("[Info][") + "SP_daemon" + "][" + __FUNCTION__ + "]:" + fmt).c_str(), \
        ##__VA_ARGS__)

#define WLOGW(fmt, ...) \
    SpLog(SP_LOG_WARN, true, (std::string("[Warning][") + "SP_daemon" + "][" + __FUNCTION__ + "]:" + fmt).c_str(), \
        ##__VA_ARGS__)

#define WLOGE(fmt, ...) \
    SpLog(SP_LOG_ERROR, true, (std::string("[Error][") + "SP_daemon" + "][" + __FUNCTION__ + "]:" + fmt).c_str(), \
        ##__VA_ARGS__)

void EnableWriteLogAndDeleteOldLogFiles();
void EscapeForCSV(std::string str);
} // namespace SmartPerf
} // namespace OHOS
#endif // OHOS_SP_LOG_H