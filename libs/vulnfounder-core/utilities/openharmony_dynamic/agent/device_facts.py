"""设备事实库（自动化方案 §11.3）：跨任务设备级事实，按 serial 分 key。

source 三态：llm-recon（侦查声称）/ validator-verified（校验器复核通过）/ manual（人工）。
staleness 语义：volatile 事实（PID 等）每次用前重验；stable 事实（socket 路径、
规则表内容）信任库。人工可审计可清理——整份 JSON 落盘，无黑盒。
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

_FACTS_DIR = Path(__file__).parent / "contracts" / "generated"

# 事实键 → 易变性分类（volatile 用前重验）
_VOLATILE_KEYS = {"hiview_pid", "sp_daemon_pid", "running_processes"}


class DeviceFacts:
    """单个设备和目标版本的事实集合，JSON 落盘持久化。

    ``target_revision`` 可选是为了兼容历史单元测试和离线侦查。真实动态
    运行由调用方传入目标分支后，事实文件名会同时包含版本，刷写系统或切换
    7.0 时不会继续读取同一 serial 的 6.1 stable facts。
    """

    def __init__(self, serial: str, *, store_dir: Path | None = None,
                 target_revision: str = "") -> None:
        self.serial = serial
        self.target_revision = str(target_revision or "").strip()
        revision_tag = re.sub(r"[^A-Za-z0-9._+-]+", "_", self.target_revision).strip("._-")
        suffix = f"_{revision_tag}" if revision_tag else ""
        self.path = (store_dir or _FACTS_DIR) / f"device_facts_{serial[:16]}{suffix}.json"
        self._data: dict[str, Any] = {}
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self._data = {}
        self._facts: dict[str, Any] = self._data.setdefault("facts", {})

    # ------------------------------------------------------------------
    def put(self, key: str, value: Any, *, source: str, evidence: str = "") -> None:
        if source not in ("llm-recon", "validator-verified", "manual"):
            raise ValueError(f"非法 source: {source}")
        self._facts[key] = {
            "value": value,
            "source": source,
            "evidence": evidence,
            "observed_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
            "volatile": key in _VOLATILE_KEYS,
        }
        self._flush()

    def get(self, key: str, *, default: Any = None) -> Any:
        item = self._facts.get(key)
        return item["value"] if item else default

    def get_item(self, key: str) -> dict[str, Any] | None:
        item = self._facts.get(key)
        return dict(item) if item else None

    def needs_revalidation(self, key: str) -> bool:
        """volatile 事实是否需要用前重验。"""
        item = self._facts.get(key)
        return bool(item and item.get("volatile"))

    def keys(self) -> list[str]:
        return sorted(self._facts.keys())

    def to_prompt_lines(self) -> list[str]:
        """事实清单 → 侦查上下文注入行（LLM 据此跳过已验证项）。"""
        lines: list[str] = []
        for key in sorted(self._facts):
            item = self._facts[key]
            freshness = "volatile-需重验" if item.get("volatile") else "stable"
            lines.append(
                f"- {key} = {item['value']!r} [{item['source']}/{freshness},"
                f" {item.get('observed_at', '')}]"
            )
        return lines

    def remove(self, key: str) -> None:
        self._facts.pop(key, None)
        self._flush()

    def _flush(self) -> None:
        self._data["serial"] = self.serial
        if self.target_revision:
            self._data["target_revision"] = self.target_revision
        self._data["facts"] = self._facts
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, ensure_ascii=False, indent=2),
                             encoding="utf-8")
