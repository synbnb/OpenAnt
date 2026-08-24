# OH-00D：项目内 OpenHarmony 源码库迁移测试记录

## 1. 阶段目标

将当前用于 OpenHarmony 分析的源码仓库从 OpenAnt 项目外的共享目录移动到项目内的 `source_code_base/`，使项目打包或交付时可以携带同一份源码库布局。

本阶段只处理目录迁移和完整性验证，不修改解析器、调用图、LLM 流程或 Web 仓库发现逻辑。

## 2. 修改前后逻辑

### 修改前

- OpenHarmony 仓库位于 OpenAnt 项目外：

  ```text
  /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code/
  ```

- OpenAnt 与这批源码在物理目录上分离，打包或复制 OpenAnt 时不会自然携带这些仓库。
- 当前 Web-03B 的仓库下拉框仍主要读取 `~/.openant/projects/` 和 Web 最近扫描记录，尚未自动枚举这批源码仓库。

### 修改后

- 22 个一级 OpenHarmony Git 仓库移动到：

  ```text
  /Users/shiyu/学习/hyl/new/OpenAnt/source_code_base/
  ```

- 每个仓库仍保持独立的 `.git`、提交历史和 `origin` 远程地址。
- 原共享目录不再包含这些一级仓库。
- `source_code_base/README.md` 记录了目录用途和后续使用约定。
- 运行时默认路径适配仍属于下一阶段；在适配完成前，Web-03B 不会自动把这些仓库显示到下拉框中。

## 3. 迁移清单

本次移动的仓库数量为 22 个：

```text
ability_ability_runtime
ark_js_runtime
arkui_ace_engine
arkui_napi
arkweb_arkweb_cangjie_wrapper
communication_ipc
communication_netmanager_base
communication_wifi
distributeddatamgr_datamgr_service
drivers_hdf_core
drivers_interface
drivers_peripheral
filemanagement_dfs_service
filemanagement_storage_service
multimedia_audio_framework
multimedia_camera_framework
multimedia_video_processing_engine
security_certificate_manager
security_device_auth
sensors_medical_sensor
systemabilitymgr_samgr
window_window_manager
```

## 4. 执行方式

迁移前已确认目标目录不存在；随后使用显式列出的仓库目录执行 `mv`，没有删除仓库内容，也没有重新克隆或重写 Git 历史。

目标目录：

```text
/Users/shiyu/学习/hyl/new/OpenAnt/source_code_base
```

旧目录：

```text
/Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code
```

## 5. 独立测试与结果

### 5.1 仓库数量和名称校验

检查目标目录一级子目录数量，并与上面的 22 项清单逐项比较。

结果：通过。

```text
expected_count=22
actual_count=22
missing=0
unexpected=0
```

### 5.2 Git 元数据和仓库根目录校验

对每个目标仓库执行以下等价检查：

```bash
git -C "$repo" rev-parse --show-toplevel
test -d "$repo/.git" -o -f "$repo/.git"
git -C "$repo" remote get-url origin
```

结果：通过。

```text
git_metadata=22
git_root_verified=22
origin_verified=22
failure_count=0
```

这证明移动后每个目录仍能被识别为自己的 Git 仓库，且仍配置了 `origin`；本阶段没有验证网络连通性，也没有执行 push。

### 5.3 旧目录清理状态校验

检查旧源码根目录是否还有一级子目录或文件：

```bash
find /Users/shiyu/学习/hyl/new/openharmony_reference/openharmony_source_code \
  -mindepth 1 -maxdepth 1 -print
```

结果：通过，输出为空。

```text
old_root_children=0
```

旧目录本身没有被删除，仍可作为空的历史位置；本阶段未执行递归删除。

### 5.4 项目内清单校验

新增的 `source_code_base/repositories.json` 记录了 22 个仓库的名称、相对路径和迁移时的 `origin`。使用 JSON 解析和目录枚举进行一致性检查：

```text
MANIFEST_JSON_OK entries=22 actual_dirs=22
DOCUMENT_WHITESPACE_OK files=3
GIT_METADATA_OK=22 GIT_ROOTS_OK=22 ORIGINS_OK=22 OLD_ROOT_CHILDREN=0
```

结果：通过。清单中的相对路径均指向当前存在的一级仓库；`README.md`、清单和本测试记录没有制表符或行尾空白。

## 6. 影响范围和未完成项

- 本阶段没有修改 OpenAnt 的 Go、Python、前端或解析逻辑，因此不需要重复运行全量代码测试。
- 已新增项目内目录说明文件，但 `source_code_base/` 下的 22 个子仓库仍由各自的 Git 管理，外层 OpenAnt 仓库不应把它们的全部源码当作普通文件纳入版本管理。
- 文档和历史测试记录中可能仍出现旧的外部路径；它们是历史记录，不代表运行时已经完成路径适配。
- 下一阶段需要改造源码根目录解析与 Web 仓库目录构建：默认读取 `OpenAnt/source_code_base/`，并保留显式配置覆盖能力。该阶段应在单独说明旧逻辑和新逻辑、获得确认后再修改。

## 7. 结论

OH-00D 目录迁移完成。22 个 OpenHarmony 仓库已完整移动到 OpenAnt 项目内，Git 元数据和远程地址均保留，旧源码根目录为空，未修改分析代码。运行时自动发现项目内仓库属于下一阶段工作。
