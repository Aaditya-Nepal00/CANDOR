"""
agent/tagger.py
---------------
CANDOR – Epistemic Tagger

Classifies raw tool results into one of four forensic confidence classes:
    CONFIRMED  – clean run, directly readable data
    INFERRED   – valid output requiring correlation / interpretation
    SUSPECTED  – partial output or minor errors present
    UNKNOWN    – tool failed, empty output, or critical error
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Load dead-end advisories from config
# ---------------------------------------------------------------------------

_DEAD_ENDS: dict[str, list[str]] = json.loads(
    (Path(__file__).parent / "dead_ends.json").read_text(encoding="utf-8")
)

# ---------------------------------------------------------------------------
# Heuristic keyword sets
# ---------------------------------------------------------------------------

_FAILURE = [
    "error", "exception", "traceback", "permission denied", "no such file",
    "command not found", "not found", "failed", "cannot open", "unable to",
    "segmentation fault", "killed",
]
_PARTIAL = [
    "warning", "warn:", "partial", "truncated", "incomplete", "could not",
    "no results", "0 results", "deprecated", "skipping", "unknown field",
]
_INTERPRET = [
    "offset", "inode", "entropy", "hash", "md5", "sha1", "sha256", "base64",
    "hex dump", "strings found", "signature", "magic bytes", "cluster", "sector",
]

_SUMMARY_MAX = 200
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    confidence_class: str
    tool_name: str
    timestamp: str
    evidence_summary: str
    reasoning: str
    dead_ends: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "confidence_class": self.confidence_class,
            "tool_name": self.tool_name,
            "timestamp": self.timestamp,
            "evidence_summary": self.evidence_summary,
            "reasoning": self.reasoning,
            "dead_ends": self.dead_ends,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ---------------------------------------------------------------------------
# Core tagger
# ---------------------------------------------------------------------------

class EpistemicTagger:
    """Classify a forensic tool result into an epistemic confidence class."""

    def tag(self, tool_result: dict[str, Any]) -> Finding:
        """
        Parameters
        ----------
        tool_result : dict with keys ``tool``, ``output``, ``error``, ``timestamp``

        Returns
        -------
        Finding
        """
        self._validate(tool_result)

        tool  = tool_result["tool"].strip()
        out   = (tool_result["output"] or "").strip()
        err   = (tool_result["error"]  or "").strip()
        ts    = self._normalise_ts(tool_result["timestamp"])

        cls, reason = self._classify(tool, out, err)
        summary = (out or err)[:_SUMMARY_MAX] + ("…" if len(out or err) > _SUMMARY_MAX else "")

        return Finding(
            confidence_class=cls,
            tool_name=tool,
            timestamp=ts,
            evidence_summary=summary,
            reasoning=reason,
            dead_ends=list(_DEAD_ENDS[cls]),   # copy so callers can't mutate config
        )

    # ------------------------------------------------------------------
    # Classification ladder (first match wins)
    # ------------------------------------------------------------------

    def _classify(self, tool: str, out: str, err: str) -> tuple[str, str]:
        ol, el = out.lower(), err.lower()
        has_out, has_err = bool(out), bool(err)

        # UNKNOWN
        if not has_out:
            snippet = f" Error snippet: {err[:120]!r}" if has_err else ""
            return "UNKNOWN", (
                f"Tool '{tool}' produced no usable output.{snippet}"
            )

        # SUSPECTED — output + any error present
        if has_err:
            return "SUSPECTED", (
                f"Tool '{tool}' returned output alongside error output, "
                "suggesting a partial or degraded run."
            )

        # SUSPECTED — output matches partial-result keywords
        m = self._first_match(ol, _PARTIAL)
        if m:
            return "SUSPECTED", (
                f"Tool '{tool}' output contains {m!r}, "
                "suggesting incomplete or ambiguous results."
            )

        # INFERRED — output has low-level forensic artefact indicators
        m = self._first_match(ol, _INTERPRET)
        if m:
            return "INFERRED", (
                f"Tool '{tool}' output contains forensic artefact indicator {m!r}. "
                "Valid output, but requires correlation with additional evidence."
            )

        # CONFIRMED
        return "CONFIRMED", (
            f"Tool '{tool}' ran successfully with no errors and returned "
            "substantive, directly readable output."
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate(r: dict[str, Any]) -> None:
        if not isinstance(r, dict):
            raise TypeError(f"tool_result must be dict, got {type(r).__name__!r}")
        for k in ("tool", "output", "error", "timestamp"):
            if k not in r:
                raise ValueError(f"tool_result missing required key: {k!r}")

    @staticmethod
    def _first_match(text: str, patterns: list[str]) -> str:
        return next((p for p in patterns if p in text), "")

    @staticmethod
    def _normalise_ts(raw: str) -> str:
        if raw and _TS_RE.match(raw):
            return raw
        return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------

def tag_result(tool_result: dict[str, Any]) -> dict[str, Any]:
    """Module-level shorthand – returns a plain dict."""
    return EpistemicTagger().tag(tool_result).to_dict()


# ---------------------------------------------------------------------------
# Self-test  (python agent/tagger.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _samples = [
        {"tool": "volatility3",  "output": "PID   PPID  Name\n 4  0  System\n 88  4  smss.exe", "error": "",                                    "timestamp": "2026-05-14T08:00:00Z"},
        {"tool": "log2timeline", "output": "SHA256: a3f1... entropy: 7.92 offset: 0x1A4C",        "error": "",                                    "timestamp": "2026-05-14T08:05:00Z"},
        {"tool": "fls",          "output": "r/r 12345: suspicious.exe",                            "error": "Warning: inode table truncated",       "timestamp": "2026-05-14T08:10:00Z"},
        {"tool": "strings",      "output": "",                                                      "error": "Permission denied: /dev/sda",          "timestamp": "2026-05-14T08:15:00Z"},
    ]
    tagger = EpistemicTagger()
    for s in _samples:
        print(tagger.tag(s).to_json())
        print("-" * 60)
