# OH-SL-03 真实目标任务定位演练记录

日期：2026-08-28  
目标：`/dev/unix/socket/paramservice`  
实例：用户提供的 OpenGrok `openharmony` 项目  
目的：验证当前新增的 OpenGrok 客户端能否完成一次真实源码定位任务。

## 1. 本次实际调用

使用 `core.source_locator.OpenGrokClient`，没有使用 shell grep，也没有修改远程 OpenGrok：

```text
probe()
search(path="param_service.c", file_type="c")
search(definition="InitParamService", file_type="c")
search(symbol="OnIncomingConnect", file_type="c")
search(full="/dev/unix/socket/paramservice")
search(full="PIPE_NAME", file_type="c")
read_source("/openharmony/base/startup/init/services/param/include/param_utils.h")
read_source("/openharmony/base/startup/init/services/param/linux/param_service.c")
```

源码读取均设置了字节上限，响应正文没有写入日志。

## 2. 定位结果

### 2.1 服务端候选文件

`path=param_service.c&type=c` 返回 2 个文件：

```text
/openharmony/base/startup/init/services/param/liteos/param_service.c
/openharmony/base/startup/init/services/param/linux/param_service.c
```

### 2.2 初始化函数

`def=InitParamService&type=c` 返回：

```text
/openharmony/base/startup/init/services/param/liteos/param_service.c:62
/openharmony/base/startup/init/services/param/linux/param_service.c:412
```

### 2.3 接收回调

`symbol=OnIncomingConnect&type=c` 返回 2 个生产代码候选：

```text
/openharmony/base/startup/init/services/param/linux/param_message.h
/openharmony/base/startup/init/services/param/linux/param_service.c
```

### 2.4 宏到 socket 路径

读取 `param_utils.h` 后确认：

```text
第 79 行：CLIENT_PIPE_NAME 定义为 /dev/unix/socket/paramservice
第 80 行：PIPE_NAME 在启动测试路径前缀后拼接同一 socket 路径
```

读取 Linux `param_service.c` 后确认：

```text
第 377 行：OnIncomingConnect(LoopHandle, TaskHandle)
第 412 行：InitParamService(void)
第 441 行：info.server = PIPE_NAME
第 444 行：info.incomingConnect = OnIncomingConnect
```

### 2.5 证据链

当前工具可以形成以下源码证据链：

```text
/dev/unix/socket/paramservice
  → param_utils.h 中的 CLIENT_PIPE_NAME / PIPE_NAME
  → param_service.c 的 InitParamService
  → info.server = PIPE_NAME
  → info.incomingConnect = OnIncomingConnect
  → OnIncomingConnect 函数实现
```

这条链条是通过真实 OpenGrok 搜索和 raw 源码读取得到的，不是模型猜测。

## 3. 效果与不足

### 已经有效的部分

- 能连接真实 OpenGrok 实例并完成能力探测；
- 能用定义搜索定位函数，而不是只依赖全文搜索；
- 能读取被 REST `/file/content` 保护的源码，并自动回退到 `/raw`；
- 能验证宏定义、服务路径、初始化函数和接收回调之间的关系；
- 能保留搜索原文和清洗后证据，便于后续审计。

### 当前不能完成的部分

- `full=/dev/unix/socket/paramservice` 返回 94 个结果，包含 SELinux、日志和生成/构建内容；当前客户端还没有生产代码排序和证据评分；
- `PIPE_NAME` 全文搜索也会命中 Linux 内核等无关代码，不能把结果列表直接交给 LLM；
- OpenGrok 的 `/projects/*`、`/list`、`/file/*` 元数据接口在该实例需要 Bearer token；当前客户端没有仓库映射接口；
- 目前只能得到 OpenHarmony monorepo 内的源码路径，不能可靠确认对应 GitCode 仓库名、revision 或 manifest 映射；
- 没有 GitCode allowlist、clone、clone 后校验和用户确认状态机，因此尚未完成“定位并拉取仓库”的完整任务。

## 4. 结论

当前工具已经能有效完成“从 socket 名称定位到服务端源码证据”的第一段任务，尤其适合函数定义、宏引用和初始化回调核验；它还不能独立完成“确定对应 GitCode 仓库并拉取到 `source_code_base`”。下一阶段应先增加确定性的结果排序/证据对象和 Manifest/仓库映射，再接入 Agent，而不是让模型直接从 94 条全文结果中猜仓库。
