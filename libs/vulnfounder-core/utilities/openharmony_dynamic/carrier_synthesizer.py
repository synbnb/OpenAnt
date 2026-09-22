"""载体合成器（自动化方案 §10 L2/L3）：HAP/native 模板不再假设全覆盖。

L1 槽位模板（transports/hap.py 现状，零 LLM）覆盖"≤3 帧单向文本协议"；
握手协商、二进制协议、>3 帧、响应依赖帧、多端点协同需要 L2/L3：

L2 载体合成（Index.ets）：
  LLM 起草完整 Index.ets（自由用 socket/fileIo API）
  → 确定性校验（§10.2）：import 白名单、槽位保持、危险模式扫描
  → hvigor 构建 → 真机"合法请求自证"（HAP_POC_START 日志出现 = 载体可运行）
  → 一次性人工批准 → 存为族级模板（carrier_templates/），L1 复用零人工。

L3 native 载体扩展（unix_client.c 变体）：同 L2 模式，
  源码白名单（禁 system/popen/exec 族）+ clang 交叉编译 + 设备自证。

人工审查成本 O(协议族数) 而非 O(样本数)：族级模板入库后每次运行零人工。
首次合成永远停 REQUIRES_HUMAN_APPROVAL——绝不带未批准载体上正式试跑。
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .transports.base import TransportError

# ---------------------------------------------------------------------------
# §10.2 确定性校验规则表（代码管控，LLM 无配置权）
# ---------------------------------------------------------------------------

# import 白名单（§10.2 规则 1）：仅声明集；网络下载/敏感 API 出现即拒绝
_IMPORT_WHITELIST = {
    "@ohos.net.socket", "@ohos.hilog", "@ohos.file.fs",
    "@ohos.file.fs_info", "@ohos.bundle.appControl",
}
_IMPORT_RE = re.compile(r"import\s+\w+\s+from\s+['\"]([^'\"]+)['\"]")

# L3 源码禁用符号：不调用 shell、不执行派生命令（§7.2 / §9.1 硬约束）
_L3_FORBIDDEN_RE = re.compile(
    r"\b(system|popen|exec[lv][pe]?|fork|dlopen)\s*\("
)

# 危险模式扫描（§10.2 规则 3）
_DANGEROUS_RE = re.compile(
    r"require\s*\(\s*[^'\"]"          # require 动态拼接
    r"|\beval\s*\("
    r"|\bnew\s+Function\s*\("
)

# 槽位保持（§10.2 规则 2）：契约占位符至少出现一次（可追溯性）
# 两类合法占位符：runner 运行期占位符（_KNOWN_PLACEHOLDERS）+ HAP 传输槽位
# （transports/hap.py _PLACEHOLDER_MAP，field_values 参数化）
_HAP_TRANSPORT_PLACEHOLDERS = {
    "__TARGET__", "__MODE__", "__HOST__", "__PORT__", "__LOCAL_PATH__",
    "__MARKER__", "__FIRST__", "__SECOND__", "__THIRD__",
}
_KNOWN_PLACEHOLDERS = {
    "__SRC_FILE__", "__STACK_FILE__", "__CPU_FILE__", "__MARKER__",
    "__RUN_PATTERN__", "__RUN_DIR__", "__MARKER_PATH__",
    *_HAP_TRANSPORT_PLACEHOLDERS,
}
_PLACEHOLDER_RE = re.compile(r"__[A-Z_]+__")

_HAP_POC_START = "HAP_POC_START"   # 自证日志锚（与模板/合成的 aboutToAppear 约定一致）

_TEMPLATES_DIR = Path(__file__).parent / "carrier_templates"
_HAP_PROJECT = (
    Path(__file__).resolve().parents[5] / "evaluation_dataset" / "vulnerability" /
    "result" / "hap_poc_suite" / "dp01_hap"
)
_TOOLCHAIN_ROOT = (
    Path(__file__).resolve().parents[1] / "dynamic_tester" / "toolchains" /
    "commandline-tools-mac-arm64-6.1.0.860" / "command-line-tools"
)
_CLANG = _TOOLCHAIN_ROOT / "sdk/default/openharmony/native/llvm/bin/aarch64-unknown-linux-ohos-clang"
_SYSROOT = _TOOLCHAIN_ROOT / "sdk/default/openharmony/native/sysroot"


# ---------------------------------------------------------------------------
# 结果类型（与 descriptor_synthesizer 同款诚实状态机）
# ---------------------------------------------------------------------------

@dataclass
class CarrierSynthesisResult:
    """载体合成结果：approved 前永远停在 REQUIRES_HUMAN_APPROVAL。"""

    status: str                        # REQUIRES_HUMAN_APPROVAL / REJECTED_VALIDATION / REQUIRES_PROTOCOL_REVIEW / APPROVED
    kind: str = ""                     # hap_index / native_client
    source: str = ""                   # LLM 起草的完整源码
    errors: list[str] = field(default_factory=list)
    validation: dict[str, Any] = field(default_factory=dict)
    build_log_tail: str = ""
    llm_used: bool = False
    template_path: str = ""            # APPROVED 后入库的族级模板路径

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status, "kind": self.kind,
            "errors": list(self.errors), "validation": dict(self.validation),
            "build_log_tail": self.build_log_tail, "llm_used": self.llm_used,
            "template_path": self.template_path,
            "source_sha256": hashlib.sha256(self.source.encode()).hexdigest()[:12]
            if self.source else "",
        }


# ---------------------------------------------------------------------------
# LLM 基础设施（与 refine_loop / contract_compiler 相同复用路径，不新建通道）
# ---------------------------------------------------------------------------

def _llm_binding():
    try:
        root = Path(__file__).resolve().parents[3]
        core = str(root / "libs" / "vulnfounder-core")
        if core not in sys.path:
            sys.path.insert(0, core)
        from utilities.llm.helpers import simple_text  # noqa: PLC0415
        from utilities.llm.registry import (  # noqa: PLC0415
            build_phase_registry,
            load_config_file,
            resolve_llm_config,
        )

        cf = load_config_file()
        lc = resolve_llm_config(cf, None)
        registry = build_phase_registry(cf, lc)
        return registry.get("dynamic_test"), simple_text
    except Exception:  # noqa: BLE001
        return None


_CARRIER_SYSTEM_PROMPT = (
    "你是 OpenHarmony 载体合成器。既有 HAP 模板只覆盖 ≤3 帧单向文本协议，"
    "无法表达握手协商/二进制协议/>3 帧/响应依赖帧。请起草完整 Index.ets：\n"
    "硬规则：\n"
    "1. 只允许 import：@ohos.net.socket / @ohos.hilog / @ohos.file.fs（白名单外整份作废）。\n"
    "2. 禁 require 动态拼接 / eval / new Function。\n"
    "3. 契约槽位占位符（如 __MARKER__ __HOST__ __PORT__）至少出现一次——"
    "运行期由 runner 替换为本轮具体值；占位符原样留在字符串/常量里，不要自行赋值。\n"
    "4. aboutToAppear 里必须输出 hilog.info(DOMAIN, TAG, `HAP_POC_START ...`)（自证锚）。\n"
    "5. 只发送受控探针载荷，不得尝试提权/下载/写系统目录。\n"
    "6. ArkTS 严格模式：禁止无类型对象字面量（arkts-no-untyped-obj-literals）——"
    "socket 地址/发送参数用**内联字面量直接写在 API 调用参数里**"
    "（如 udp.send({ data: X, address: { address: HOST, family: 1, port: PORT } })），"
    "不要先赋给独立 const 变量再传入；Number()/类型转换在 const 声明处完成。\n"
    "7. close() 等可能抛异常的调用包 try/catch。\n"
    "只输出代码（可带 ``` 代码围栏），不要解释文字。"
)


def _strip_code_fence(text: str) -> str:
    """剥 ``` 围栏与语言标记（ts/typescript/ets/arkts）：第一块以语言词开头时剥首行。"""
    text = text.strip()
    if "```" not in text:
        return text
    blocks = [b for b in text.split("```") if b.strip()]
    if not blocks:
        return text
    body = blocks[0]
    first_line, _, rest = body.partition("\n")
    if first_line.strip() in ("ts", "typescript", "ets", "arkts"):
        body = rest
    return body.strip()


def _llm_carrier_source(context: str) -> str | None:
    pair = _llm_binding()
    if pair is None:
        return None
    binding, simple_text = pair
    text = simple_text(binding, context, system=_CARRIER_SYSTEM_PROMPT, max_tokens=12000)
    return _strip_code_fence(text) or None


# ---------------------------------------------------------------------------
# §10.2 确定性校验（规则 1-3；规则 4 构建自证在 synthesize 里）
# ---------------------------------------------------------------------------

def validate_hap_carrier(source: str, *, required_placeholders: set[str] | None = None
                         ) -> tuple[dict[str, Any], list[str]]:
    """Index.ets 载体确定性校验（§10.2）。返回 (validation, errors)；空 errors = 全过。"""
    errors: list[str] = []
    validation: dict[str, Any] = {}

    imports = _IMPORT_RE.findall(source)
    bad_imports = [i for i in imports if i not in _IMPORT_WHITELIST]
    validation["imports"] = imports
    if bad_imports:
        errors.append(f"import 白名单外: {bad_imports}（允许: {sorted(_IMPORT_WHITELIST)}）")

    dangerous = _DANGEROUS_RE.findall(source)
    if dangerous:
        errors.append(f"危险模式: {dangerous}")

    found = set(_PLACEHOLDER_RE.findall(source))
    unknown = found - _KNOWN_PLACEHOLDERS
    if unknown:
        errors.append(f"未知占位符: {sorted(unknown)}（runner 支持集 {sorted(_KNOWN_PLACEHOLDERS)}）")
    required = required_placeholders or {"__MARKER__"}
    missing = required - found
    if missing:
        errors.append(f"槽位保持失败: {sorted(missing)} 至少出现一次（可追溯性）")
    if _HAP_POC_START not in source:
        errors.append(f"自证锚缺失: aboutToAppear 须输出 {_HAP_POC_START}")
    validation["placeholders"] = sorted(found)
    return validation, errors


def validate_native_carrier(source: str) -> tuple[dict[str, Any], list[str]]:
    """unix_client.c 变体源码校验（L3 同 §10.2 模式）。返回 (validation, errors)。"""
    errors: list[str] = []
    validation: dict[str, Any] = {}
    forbidden = _L3_FORBIDDEN_RE.findall(source)
    if forbidden:
        errors.append(f"源码白名单外（禁 shell/exec 族）: {forbidden}")
    # 逐系统调用 report 硬要求（§9.1）：客户端发送失败与服务拒绝必须可分
    if "report(" not in source or '"result"' not in source:
        errors.append("缺逐系统调用 report()/result 行输出（§9.1 硬要求）")
    validation["forbidden_hits"] = forbidden
    return validation, errors


# ---------------------------------------------------------------------------
# 构建自证（§10.2 规则 4）
# ---------------------------------------------------------------------------

def _build_hap(source: str, *, contract_id: str, out_root: Path | None = None) -> tuple[Path | None, str]:
    """载体 Index.ets → hvigor 构建 → 签名。返回 (signed_hap | None, log_tail)。"""
    from .transports.hap import (
        HapTransport,
        _HVIGORW, _NODE, _SIGN_JAR, _TEMPLATE_PROJECT, CERT_DIR, KEY_ALIAS, KEY_PWD,
    )

    if not _TEMPLATE_PROJECT.exists():
        return None, f"HAP 模板工程缺失: {_TEMPLATE_PROJECT}"
    out_dir = (out_root or Path(tempfile.gettempdir())) / f"vf-carrier-{contract_id}"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    project = out_dir / "project"
    shutil.copytree(_TEMPLATE_PROJECT, project,
                    ignore=shutil.ignore_patterns(".hvigor", "build", "signing", "*.log"))
    index_path = project / "Entry/src/main/ets/pages/Index.ets"
    index_path.write_text(source, encoding="utf-8")
    (project / "local.properties").write_text(
        f"sdk.dir={_TOOLCHAIN_ROOT / 'sdk'}\nnodejs.dir={_NODE}\n", encoding="utf-8")

    # 载体合成和普通 HAP 传输必须使用同一套隔离构建环境。否则普通
    # 探针已经能离线构建，但 L2 自定义 Index.ets 又会落回宿主机
    # ~/.hvigor，并在权限或联网受限时失败。
    hvigor_user_home = out_dir / ".hvigor-user"
    hvigor_user_home.mkdir(parents=True, exist_ok=True)
    HapTransport._stage_offline_hvigor_dependencies(project, hvigor_user_home)

    import os

    env = {
        **dict(os.environ),
        "NODE_HOME": str(_NODE),
        "HVIGOR_USER_HOME": str(hvigor_user_home),
    }
    build = subprocess.run(
        [str(_HVIGORW), "assembleApp", "--no-daemon"], cwd=str(project), env=env,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        shell=False, timeout=600, check=False,
    )
    log = build.stdout.decode("utf-8", errors="replace")
    unsigned = sorted(project.rglob("entry-default-unsigned.hap"))
    if not unsigned:
        return None, log[-1500:]
    signed = out_dir / "entry-default-signed.hap"
    sign_cmd = [
        "java", "-jar", str(_SIGN_JAR), "sign-app", "-mode", "localSign",
        "-keyAlias", KEY_ALIAS, "-keyPwd", KEY_PWD,
        "-appCertFile", str(CERT_DIR / "oh_release_chain.cer"),
        "-profileFile", str(CERT_DIR / "oh_profile8.p7b"),
        "-inFile", str(unsigned[0]),
        "-signAlg", "SHA256withECDSA",
        "-keystoreFile", str(CERT_DIR / "oh_release.p12"), "-keystorePwd", KEY_PWD,
        "-outFile", str(signed), "-compatibleVersion", "23", "-signCode", "0",
    ]
    sign = subprocess.run(sign_cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, shell=False, timeout=300, check=False)
    log += "\n" + sign.stdout.decode("utf-8", errors="replace")
    return (signed if signed.exists() else None), log[-1500:]


def _self_check_hap(hdc, hap: Path) -> tuple[bool, str]:
    """真机合法请求自证：安装 → 启动 → hilog 出现 HAP_POC_START = 载体可运行。

    hilog 过滤在设备侧完成（hilog -x | grep）：裸 dump 实测 >256KB 触发
    HDCClient.max_output_bytes 截断，目标行落在截断区导致自证永远 miss
    （与 §7.1 hilog -x 缓冲积压同根因——先过滤再回传）。
    """
    rec = hdc.run(["install", "-r", str(hap)], purpose="carrier:selfcheck-install",
                  timeout_seconds=120)
    if rec.returncode != 0 or "successfully" not in (rec.stdout + rec.stderr).lower():
        return False, f"安装失败: {rec.stdout} {rec.stderr}"
    try:
        hdc.run(["shell", "aa", "force-stop", "com.security.research.trigger"],
                purpose="carrier:selfcheck-stop")
        hdc.run(["shell", "hilog", "-r"], purpose="carrier:selfcheck-hilog-clear")
        start = hdc.run(["shell", "aa", "start", "-b", "com.security.research.trigger",
                         "-a", "EntryAbility"], purpose="carrier:selfcheck-start")
        if start.returncode != 0:
            return False, f"aa start 失败: {start.stdout} {start.stderr}"
        import time

        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            log = hdc.run(["shell", "hilog -x | grep HAP_POC"],
                          purpose="carrier:selfcheck-log")
            if _HAP_POC_START in (log.stdout or ""):
                return True, "HAP_POC_START observed"
            time.sleep(2)
        return False, "15s 内未观测到 HAP_POC_START（载体未运行或 hilog 锚缺失）"
    finally:
        hdc.run(["shell", "aa", "force-stop", "com.security.research.trigger"],
                purpose="carrier:selfcheck-cleanup")
        hdc.run(["uninstall", "com.security.research.trigger"],
                purpose="carrier:selfcheck-uninstall")


def _build_native(source: str, *, contract_id: str) -> tuple[Path | None, str]:
    """unix_client.c 变体 → clang 交叉编译。返回 (binary | None, log_tail)。"""
    if not _CLANG.exists():
        return None, f"交叉编译器不存在: {_CLANG}"
    out = Path(tempfile.gettempdir()) / f"vf_carrier_{contract_id}"
    src_tmp = Path(tempfile.gettempdir()) / f"vf_carrier_{contract_id}.c"
    src_tmp.write_text(source, encoding="utf-8")
    cmd = [str(_CLANG), f"--sysroot={_SYSROOT}", "-O2", "-static", "-Wall",
           "-o", str(out), str(src_tmp)]
    completed = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=False, timeout=120, check=False)
    if completed.returncode != 0:
        return None, completed.stderr.decode("utf-8", errors="replace")[-2000:]
    return out, "clang ok"


# ---------------------------------------------------------------------------
# 合成主流程
# ---------------------------------------------------------------------------

def synthesize_hap_carrier(
    context: str,
    *,
    contract_id: str,
    hdc=None,
    required_placeholders: set[str] | None = None,
    source_override: str | None = None,
) -> CarrierSynthesisResult:
    """L2：上下文（传输层源码/既有模板/端口事实）→ LLM 起草 Index.ets
    → 确定性校验 → 构建自证 → REQUIRES_HUMAN_APPROVAL。

    source_override 用于测试注入（跳过 LLM）。自证失败/构建失败同样停在
    REQUIRES_HUMAN_APPROVAL 并带日志（§10.2 规则 4）。
    """
    llm_used = source_override is None
    source = source_override or _llm_carrier_source(context)
    if not source:
        return CarrierSynthesisResult(
            status="REQUIRES_PROTOCOL_REVIEW", kind="hap_index",
            errors=["LLM 不可用或未输出代码"], llm_used=llm_used,
        )

    validation, errors = validate_hap_carrier(source, required_placeholders=required_placeholders)
    if errors:
        return CarrierSynthesisResult(
            status="REJECTED_VALIDATION", kind="hap_index", source=source,
            errors=errors, validation=validation, llm_used=llm_used,
        )

    if hdc is not None:
        # 构建自证（§10.2 规则 4）：真实设备上跑通才算载体可运行
        hap, build_log = _build_hap(source, contract_id=contract_id)
        if hap is None:
            return CarrierSynthesisResult(
                status="REQUIRES_HUMAN_APPROVAL", kind="hap_index", source=source,
                errors=["hvigor 构建/签名未产出 unsigned HAP（日志尾部见 build_log_tail）"],
                validation=validation, build_log_tail=build_log, llm_used=llm_used,
            )
        ok, detail = _self_check_hap(hdc, hap)
        if not ok:
            return CarrierSynthesisResult(
                status="REQUIRES_HUMAN_APPROVAL", kind="hap_index", source=source,
                errors=[f"真机合法请求自证未过: {detail}"],
                validation=validation, build_log_tail=build_log, llm_used=llm_used,
            )
        validation["self_check"] = detail
    else:
        validation["self_check"] = "skipped（离线：无设备通道）"

    return CarrierSynthesisResult(
        status="REQUIRES_HUMAN_APPROVAL", kind="hap_index", source=source,
        validation=validation, llm_used=llm_used,
    )


def synthesize_native_carrier(
    context: str,
    *,
    contract_id: str,
    source_override: str | None = None,
) -> CarrierSynthesisResult:
    """L3：上下文 → LLM 起草 unix_client.c 变体 → 源码白名单校验 →
    clang 交叉编译 → REQUIRES_HUMAN_APPROVAL（设备自证由批准后首次运行承担）。"""
    llm_used = source_override is None
    source = source_override or _llm_carrier_source(context)
    if not source:
        return CarrierSynthesisResult(
            status="REQUIRES_PROTOCOL_REVIEW", kind="native_client",
            errors=["LLM 不可用或未输出代码"], llm_used=llm_used,
        )

    validation, errors = validate_native_carrier(source)
    if errors:
        return CarrierSynthesisResult(
            status="REJECTED_VALIDATION", kind="native_client", source=source,
            errors=errors, validation=validation, llm_used=llm_used,
        )

    binary, build_log = _build_native(source, contract_id=contract_id)
    if binary is None:
        return CarrierSynthesisResult(
            status="REQUIRES_HUMAN_APPROVAL", kind="native_client", source=source,
            errors=["clang 交叉编译失败（日志尾部见 build_log_tail）"],
            validation=validation, build_log_tail=build_log, llm_used=llm_used,
        )
    validation["build"] = "clang ok"
    return CarrierSynthesisResult(
        status="REQUIRES_HUMAN_APPROVAL", kind="native_client", source=source,
        validation=validation, llm_used=llm_used,
    )


# ---------------------------------------------------------------------------
# 族级模板库（一次性人工批准后入库，L1 复用零人工）
# ---------------------------------------------------------------------------

def approve_and_register(result: CarrierSynthesisResult, *, family: str) -> str:
    """人工批准后存为族级模板（同 family 不覆盖既有模板）。

    真实审批动作（终端确认）由调用方完成；本函数只负责入库。
    返回模板路径。
    """
    if result.status != "REQUIRES_HUMAN_APPROVAL" or not result.source:
        raise TransportError(f"仅 REQUIRES_HUMAN_APPROVAL 状态可入库（当前 {result.status}）")
    _TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    ext = "ets" if result.kind == "hap_index" else "c"
    path = _TEMPLATES_DIR / f"{family}.{ext}"
    if path.exists():
        raise TransportError(f"族级模板已存在（同 id 不覆盖，需人工介入）: {path}")
    path.write_text(result.source, encoding="utf-8")
    result.template_path = str(path)
    return str(path)


def get_family_template(family: str, kind: str = "hap_index") -> str | None:
    """读取已批准的族级模板（L1 复用入口）；不存在返回 None。"""
    ext = "ets" if kind == "hap_index" else "c"
    path = _TEMPLATES_DIR / f"{family}.{ext}"
    return path.read_text(encoding="utf-8") if path.exists() else None
