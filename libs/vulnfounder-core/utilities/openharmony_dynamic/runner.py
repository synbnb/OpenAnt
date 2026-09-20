"""运行器（§4.2 状态机）：anchor → baseline → mutate → observe → verdict → cleanup。

编排一次契约执行的全部阶段；每阶段产物落入 RunRecord（可追溯到 observation）。
样本差异全部来自契约 JSON；本模块不含样本逻辑。
"""

from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .contracts import load_contract
from .hdc_client import HDCClient
from .models import ArtifactForm, Contract, Observation, OracleResult, Verdict, new_run_id
from .observation.oracles import (
    OracleError,
    clear_artifacts,
    evaluate_artifact_differential,
    plant_exfil_file,
)
from .observation.snapshot import (
    device_clock,
    dump_hilog,
    filter_hilog,
    snapshot_paths,
)
from .protocols import get_descriptor
from .transports.base import INPUT_DELIVERED
from .verdict import build_verdict

if TYPE_CHECKING:
    pass

_RUN_DIR_ROOT = "/data/local/tmp/vf"
_PATTERN_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"


def _random_pattern(length: int = 12) -> str:
    return "vf" + "".join(secrets.choice(_PATTERN_ALPHABET) for _ in range(length - 2))


def _substitute(obj: Any, mapping: dict[str, str]) -> None:
    """对契约对象内 str 字段/字典值/列表项做占位符替换。

    （__SRC_FILE__ / __RUN_PATTERN__ / __RUN_DIR__）。dataclass 的普通属性走
    `vars()`；容器属性（dict / list / 嵌套 dataclass）递归下钻。
    """
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, str):
                for old, new in mapping.items():
                    if old in value:
                        obj[key] = value.replace(old, new)
                        value = obj[key]
            else:
                _substitute(value, mapping)
        return
    if isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, str):
                for old, new in mapping.items():
                    if old in item:
                        obj[i] = item.replace(old, new)
            else:
                _substitute(item, mapping)
        return
    if hasattr(obj, "__dict__"):
        namespace = vars(obj)
        for key, value in namespace.items():
            if isinstance(value, str):
                for old, new in mapping.items():
                    if old in value:
                        namespace[key] = value.replace(old, new)
                        value = namespace[key]
            else:
                _substitute(value, mapping)


@dataclass
class RunRecord:
    run_id: str
    contract_id: str
    started_at: float
    finished_at: float = 0.0
    pattern: str = ""
    state: str = "COMPILED"
    reachability: str = "INPUT_NOT_SENT"
    observations: list[dict[str, Any]] = field(default_factory=list)
    verdict: dict[str, Any] = field(default_factory=dict)
    hilog_hits: list[dict[str, Any]] = field(default_factory=list)
    command_count: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "contract_id": self.contract_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "pattern": self.pattern,
            "state": self.state,
            "reachability": self.reachability,
            "observations": list(self.observations),
            "verdict": dict(self.verdict),
            "hilog_hits": list(self.hilog_hits),
            "command_count": self.command_count,
            "error": self.error,
        }


class Runner:
    """一次契约执行的状态机编排。"""

    def __init__(self, hdc: HDCClient, *, artifacts_root: Path | None = None,
                 on_event: "callable | None" = None) -> None:
        self.hdc = hdc
        self.artifacts_root = artifacts_root or Path("test_records/ohos-dynamic-v2/runs")
        self.artifacts_root.mkdir(parents=True, exist_ok=True)
        # 可选进度回调：on_event({"event": str, "detail": str})（实时展示用，
        # 失败绝不影响执行）。事件点：阶段状态机推进 + run_id 生成。
        self.on_event = on_event

    def _emit(self, event: str, detail: str = "") -> None:
        if self.on_event is None:
            return
        try:
            self.on_event({"event": event, "detail": detail})
        except Exception:  # noqa: BLE001 — 进度回调失败不影响执行
            pass

    # ------------------------------------------------------------------
    def run(self, contract: Contract) -> RunRecord:
        run_id = new_run_id()
        rec = RunRecord(run_id=run_id, contract_id=contract.contract_id, started_at=time.time())
        rec.pattern = _random_pattern()
        run_dir = f"{_RUN_DIR_ROOT}/{run_id}-{contract.contract_id}"
        transport = None
        self._emit("run_started", f"{run_id} 契约 {contract.contract_id}")
        try:
            # 1. 参数解析：契约模板占位符 → 具体值（含 run 唯一图案回填）
            params = self._resolve_params(contract, run_id, run_dir, rec.pattern)
            rec.state = "ANCHORED"

            # 2. 传输层构造
            transport = self._make_transport(contract)
            descriptor = get_descriptor(contract.protocol.descriptor_id)

            # 3. 清理 + 预埋（exfil 源文件 + 契约声明的前置文件），再采执行前快照（BASELINED 强制节点）
            oracle_paths = {f.path for f in contract.oracle.artifact_forms if f.path}
            # Exp 契约豁免路径（param_space.exp_no_plant_paths）：victim 是设备
            # 真实系统文件（如 /system/etc/hiview/*）——rm -f / 预埋写入都绝不
            # 允许（只读分区写入必失败，run 5a970e 实测 OracleError），且 Exp
            # 语义只需要"读取前就存在的文件内容外泄"，快照核对照常进行。
            no_plant = frozenset(
                str(p) for p in (getattr(contract.protocol, "param_space", None) or {})
                .get("exp_no_plant_paths", []) or []
            )
            clear_artifacts(self.hdc, contract.oracle, purpose=f"{run_id}:pre-clear",
                            skip_paths=no_plant)
            for form in contract.oracle.artifact_forms:
                if form.form == "exfil" and form.path not in no_plant:
                    ok = plant_exfil_file(self.hdc, form, purpose=f"{run_id}:plant")
                    if not ok:
                        raise OracleError(f"exfil 预埋失败: {form.path}")
            # 契约声明的前置文件（param_space.preplant）：发送前必须存在的依赖文件，
            # 内容为 run 级良性标记（不含 run_pattern，避免污染输出面导致 exfil 误报）；
            # 典型如 info_ logPath 引用的 stack 文件。
            # 【冲突跳过】preplant 路径与 oracle exfil 预埋路径相同（LLM 草案把
            # oracle 占位符展开后的具体路径也写进 preplant，实测 0891cac5/f29414f8）
            # 时跳过——oracle 预埋先写 run_pattern（判定 needle），preplant 再写
            # vf-dep- 会覆盖它 → exfil 永远 miss（假阴性）。
            param_space = getattr(contract.protocol, "param_space", None) or {}
            for tpl in param_space.get("preplant", []):
                dep = ArtifactForm(form="exfil", path=tpl, content_contains=f"vf-dep-{run_id}")
                if tpl in oracle_paths:
                    self._emit("phase_note", f"preplant 跳过（oracle 已预埋）: {tpl}")
                    continue
                ok = plant_exfil_file(self.hdc, dep, purpose=f"{run_id}:plant-dep")
                if not ok:
                    raise OracleError(f"前置文件预埋失败: {tpl}")
                oracle_paths.add(tpl)
            baseline_files = snapshot_paths(self.hdc, oracle_paths, purpose=f"{run_id}:baseline")
            baselined = True
            rec.state = "BASELINED"
            self._emit("phase", rec.state)

            # 5. 基线 hilog 锚点；清空 hilogd 缓冲（`hilog -x` 全量 dump 受主机端
            # 256KB 截断上限约束，缓冲积压时目标行会被截掉——实机实证：
            # buffer 765KB 时 SaveFreezeExt 行全部丢失，清空后 dump 仅 ~3KB）
            self.hdc.shell(["hilog", "-r"], purpose=f"{run_id}:hilog-clear")
            clock_before = device_clock(self.hdc)

            # 6. 发送（mutate）；run_dir 预创建：marker 等本轮产物路径的父目录
            # （设备侧 popen 重定向等需要目录已存在；探针实证缺失时注入载体本身失败）
            self.hdc.shell(["mkdir", "-p", run_dir], purpose=f"{run_id}:mkdir-rundir")
            if contract.entry.kind == "native_unix" or contract.entry.kind == "unix_dgram":
                from .transports.native_unix import NativeUnixTransport

                assert isinstance(transport, NativeUnixTransport)
                send_result = transport.send(
                    contract.protocol,
                    descriptor,
                    socket_path=contract.entry.endpoint,
                    drop_privs=contract.identity.drop_privs,
                    purpose=f"{run_id}:send",
                )
            elif contract.entry.kind in ("hap_udp", "hap_tcp"):
                field_values = dict(contract.protocol.field_values)
                field_values["marker"] = params["marker"]
                # 契约 frame_sequence：键名列表 → field_values 中的 first/second/third 插槽
                slots = ("first", "second", "third")
                for slot, key in zip(slots, contract.protocol.frame_sequence):
                    field_values[slot] = params.get(key, contract.protocol.field_values.get(key, ""))
                send_result = transport.build_and_run(field_values, contract_id=contract.contract_id)
            else:
                raise OracleError(f"未支持的 entry.kind: {contract.entry.kind}")
            rec.reachability = send_result.reachability
            rec.state = "MUTATED"
            self._emit("phase", rec.state)

            # 7. 效果窗口：hilog 期望存在时轮询等待（目标服务处理延迟可变，
            # 实测 hiview MergeEventLog 延迟 9~41s，固定 sleep 不可靠）；
            # 无 hilog 期望时按传输类型取固定窗口
            if contract.oracle.hilog_expectations:
                self._wait_for_hilog_expectations(
                    contract.oracle.hilog_expectations, anchor_time=clock_before,
                    record=rec, run_id=run_id,
                )
            else:
                wait_seconds = contract.protocol.param_space.get(
                    "effect_window_seconds"
                ) if contract.protocol.param_space else None
                if wait_seconds is None:
                    wait_seconds = 3.0 if contract.entry.kind in ("hap_udp", "hap_tcp") else 8.0
                time.sleep(float(wait_seconds))

            # 8. 执行后快照 + hilog 终态采集（轮询期已缓存命中则复用）
            mutated_files = snapshot_paths(self.hdc, oracle_paths, purpose=f"{run_id}:after")
            hilog_after = dump_hilog(self.hdc, purpose=f"{run_id}:hilog")
            hits: list[dict[str, Any]] = []
            for expect in contract.oracle.hilog_expectations:
                found = filter_hilog(
                    hilog_after.text,
                    tag=expect.get("tag", ""),
                    pattern=expect.get("pattern", ""),
                    window_seconds=expect.get("window", {}).get("seconds"),
                    anchor_time=clock_before,
                )
                hits.extend(found)
            rec.hilog_hits = hits

            # 9. oracle 判定（artifact_differential + hilog_expectation 联合）
            oracle_result = evaluate_artifact_differential(
                contract.oracle, baseline_files, mutated_files,
                hdc=self.hdc, run_pattern=rec.pattern,
            )
            if contract.oracle.hilog_expectations:
                hilog_ok = len(hits) >= min(
                    (e.get("min_count", 1) for e in contract.oracle.hilog_expectations), default=1
                )
                oracle_result.details["hilog_expectation"] = {"hits": len(hits), "passed": hilog_ok}
                if not hilog_ok:
                    oracle_result.effect_observed = False

            observation = Observation(
                observation_id=f"{run_id}-obs",
                run_id=run_id,
                contract_id=contract.contract_id,
                phase="mutated",
                transport=send_result.transport,
                syscalls=[],
                filesystem={p: s.to_dict() for p, s in mutated_files.items()},
                hilog_hits=hits,
            )
            rec.observations.append(observation.to_dict())
            rec.state = "OBSERVED"
            self._emit("phase", rec.state)

            # 10. verdict
            blocker = ""
            if send_result.reachability == "INPUT_REJECTED":
                blocker = "policy"
            verdict = build_verdict(
                contract_id=contract.contract_id,
                run_id=run_id,
                reachability=send_result.reachability,
                oracle=oracle_result,
                execution_identity=contract.identity.execution_identity,
                influence_blocker=blocker,
                baselined=baselined,
                status_reason_code="artifact_differential",
                gap="" if oracle_result.effect_observed else "oracle 无信号：声明 form 未全部通过",
                limitations=list(contract.limitations),
            )
            rec.verdict = verdict.__dict__.copy()
            rec.verdict["oracle"] = oracle_result.__dict__.copy()
            rec.state = "VERDICTED"
            self._emit("phase", rec.state)
        except Exception as exc:  # noqa: BLE001 — runner 顶层兜底，错误入 record
            rec.error = f"{type(exc).__name__}: {exc}"
            rec.state = "INFRA_ERROR" if rec.state in ("COMPILED", "ANCHORED") else rec.state
            self._emit("error", rec.error)
        finally:
            # 11. cleanup（契约声明的路径 + 运行目录）
            try:
                paths = [p for p in contract.cleanup.remote_paths if p and "__" not in p]
                for p in paths:
                    self.hdc.shell(["rm", "-rf", p], purpose=f"{rec.run_id}:cleanup")
                self.hdc.shell(["rm", "-rf", run_dir], purpose=f"{rec.run_id}:cleanup-rundir")
                if contract.entry.kind in ("hap_udp", "hap_tcp"):
                    if transport is None:
                        transport = self._make_transport(contract)
                    transport.cleanup()
            except Exception as exc:  # noqa: BLE001
                rec.error = rec.error or f"cleanup: {type(exc).__name__}: {exc}"
            rec.finished_at = time.time()
            rec.command_count = self.hdc.command_count()
            self._persist(rec)
        self._emit("run_finished", f"state={rec.state} pattern={rec.pattern}")
        return rec

    # ------------------------------------------------------------------
    def _wait_for_hilog_expectations(
        self,
        expectations: list[dict[str, Any]],
        *,
        anchor_time,
        record: RunRecord,
        run_id: str,
        poll_interval: float = 3.0,
        max_wait: float = 75.0,
    ) -> None:
        """轮询 hilog 直至全部期望命中或超时。

        每次循环重 dump 全量 hilog 并本地过滤；anchor 取自发送前设备时钟，
        filter_hilog 的时间窗按契约 window.seconds 裁剪。
        """
        waited = 0.0
        while True:
            hilog_after = dump_hilog(self.hdc, purpose=f"{run_id}:hilog-poll")
            all_hits: list[dict[str, Any]] = []
            for expect in expectations:
                all_hits.extend(filter_hilog(
                    hilog_after.text,
                    tag=expect.get("tag", ""),
                    pattern=expect.get("pattern", ""),
                    window_seconds=expect.get("window", {}).get("seconds"),
                    anchor_time=anchor_time,
                ))
            if len(all_hits) >= len(expectations):
                record.hilog_hits = all_hits
                return
            if waited >= max_wait:
                record.hilog_hits = all_hits
                return
            time.sleep(poll_interval)
            waited += poll_interval

    def _resolve_params(self, contract: Contract, run_id: str, run_dir: str, pattern: str) -> dict[str, str]:
        """契约模板占位符 → 本轮具体值（run 唯一图案/目录，可追溯、可否证）。"""
        params: dict[str, str] = {}
        field_values = contract.protocol.field_values
        param_space = getattr(contract.protocol, "param_space", None) or {}
        # 帧模板可在 field_values 或 param_space 声明（param_space 存放非线路字段）
        first_tpl = field_values.get("frame_first_template") or param_space.get("frame_first_template", "")
        second_tpl = field_values.get("frame_second") or param_space.get("frame_second", "")
        # src 文件目录：契约可声明（如 hiview 域才可读的 /data/log/eventlog），缺省 run_dir
        src_dir = field_values.get("src_file_dir") or param_space.get("src_file_dir")
        src_dir = src_dir or run_dir
        params["run_dir"] = run_dir
        params["src_file"] = f"{src_dir}/vf_{run_id}_src.txt"
        # HV 链：FREEZE_INFO_PATH 为 "stack,cpu" 双路径；stack 文件承载 info_ logPath
        params["stack_file"] = params["src_file"]
        params["cpu_file"] = f"{src_dir}/vf_{run_id}_cpu.txt"
        params["marker"] = f"{run_dir}/marker_{contract.contract_id}_{run_id}.txt"
        params["frame_first"] = first_tpl.replace("__MARKER_PATH__", params["marker"])
        params["frame_second"] = second_tpl
        mapping = {
            "__SRC_FILE__": params["src_file"],
            "__STACK_FILE__": params["stack_file"],
            "__CPU_FILE__": params["cpu_file"],
            "__MARKER__": params["marker"],
            # marker 完整路径（field_values 内嵌路径拼接用，如穿越载体
            # "__MARKER_PATH__/../../__CPU_FILE__"——真机实证缺失时占位符原样上线）
            "__MARKER_PATH__": params["marker"],
            "__RUN_PATTERN__": pattern,
            "__RUN_DIR__": run_dir,
        }
        _substitute(contract.oracle, mapping)
        _substitute(contract.protocol, mapping)
        _substitute(contract.cleanup, mapping)
        # cleanup 增补本轮产物文件（不删公共目录本身）；marker 目录由 run_dir 清理覆盖
        contract.cleanup.remote_paths.extend([params["stack_file"], params["cpu_file"]])
        return params

    def _make_transport(self, contract: Contract):
        if contract.entry.kind in ("native_unix", "unix_dgram"):
            from .transports.native_unix import NativeUnixTransport

            return NativeUnixTransport(self.hdc)
        if contract.entry.kind in ("hap_udp", "hap_tcp"):
            from .transports.hap import HapTransport

            return HapTransport(self.hdc)
        raise OracleError(f"未知 entry.kind: {contract.entry.kind}")

    def _persist(self, rec: RunRecord) -> None:
        out = self.artifacts_root / f"{rec.run_id}-{rec.contract_id}.json"
        out.write_text(json.dumps(rec.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
