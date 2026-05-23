"""
agent/correlator.py – CANDOR Rule-Based Cross-Correlation Engine

Runs deterministic cross-correlation on Finding dicts BEFORE LLM narrative.
Catches timestamp contradictions, missing corroboration, known-bad patterns.
All thresholds in CONFIG. No external dependencies beyond stdlib.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Configuration – every threshold in one place
# ---------------------------------------------------------------------------
CONFIG: dict[str, Any] = {
    "proximity_confirm_seconds": 300,       # 5 min
    "proximity_contradict_seconds": 3600,   # 60 min
    "simultaneity_seconds": 2,
    "artifact_type_map": {
        "amcache": "execution", "prefetch": "execution",
        "analyzemft": "filesystem", "evtx": "event_log",
        "log2timeline": "timeline",
        "volatility3": "memory",
    },
    "gap_keywords": ["gap", "missing"],
}

# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------
_TS_FMTS = [
    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%SZ", "%Y-%m-%d %H:%M:%S%z",
]

def _parse_ts(raw: str) -> datetime | None:
    """Parse an ISO-ish timestamp; returns None if unparseable."""
    if not raw:
        return None
    for fmt in _TS_FMTS:
        try:
            dt = datetime.strptime(raw.strip(), fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None

def _delta_s(a: datetime, b: datetime) -> float:
    """Absolute seconds between two datetimes."""
    return abs((a - b).total_seconds())

# ---------------------------------------------------------------------------
# Field accessors
# ---------------------------------------------------------------------------
def _tool(f: dict) -> str:
    """Normalised tool name from a finding dict."""
    return (f.get("tool_name") or f.get("tool") or "").lower().strip()

def _conf(f: dict) -> str:
    """Confidence class from a finding dict."""
    return (f.get("confidence_class") or "").upper().strip()

def _summary(f: dict) -> str:
    """Evidence summary (lowercased) from a finding dict."""
    return (f.get("evidence_summary") or "").lower()

def _atype(f: dict) -> str:
    """Artifact type category for a finding."""
    return CONFIG["artifact_type_map"].get(_tool(f), "other")

# ---------------------------------------------------------------------------
# Rule 1 – Timestamp Proximity
# ---------------------------------------------------------------------------
def _rule_timestamp_proximity(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """Compare timestamps across tools sharing an artifact type.

    Returns (confirmed_pairs, contradictions). Confirmed if within
    proximity_confirm_seconds; contradiction if beyond proximity_contradict_seconds.
    """
    climit = CONFIG["proximity_confirm_seconds"]
    xlimit = CONFIG["proximity_contradict_seconds"]
    confirmed: list[dict] = []
    contradictions: list[dict] = []
    for i, a in enumerate(findings):
        ts_a = _parse_ts(a.get("timestamp", ""))
        if not ts_a:
            continue
        for b in findings[i + 1:]:
            if _tool(a) == _tool(b) or _atype(a) != _atype(b):
                continue
            ts_b = _parse_ts(b.get("timestamp", ""))
            if not ts_b:
                continue
            delta = _delta_s(ts_a, ts_b)
            if delta <= climit:
                confirmed.append({
                    "finding_a": _tool(a), "finding_b": _tool(b),
                    "delta_seconds": delta, "rule": "timestamp_proximity",
                    "verdict": "CONFIRMED_PAIR",
                    "message": (f"{_tool(a)} and {_tool(b)} agree within "
                               f"{delta:.0f}s on {_atype(a)} activity"),
                })
            elif delta >= xlimit:
                contradictions.append({
                    "finding_a": _tool(a), "finding_b": _tool(b),
                    "delta_seconds": delta, "rule": "timestamp_proximity",
                    "verdict": "CONTRADICTION",
                    "message": (f"{_tool(a)} and {_tool(b)} timestamps differ by "
                               f"{delta:.0f}s on {_atype(a)} — possible "
                               "temporal contradiction"),
                })
    return confirmed, contradictions

# ---------------------------------------------------------------------------
# Rule 2 – Corroboration Check
# ---------------------------------------------------------------------------
def _rule_corroboration(findings: list[dict]) -> list[dict]:
    """Flag missing cross-source corroboration (Amcache↔Prefetch, MFT↔EVTX)."""
    patterns: list[dict] = []
    tools = {_tool(f): f for f in findings}
    confs = {_tool(f): _conf(f) for f in findings}
    # Amcache present but Prefetch UNKNOWN
    if "amcache" in tools and "prefetch" in tools:
        if confs.get("prefetch") == "UNKNOWN":
            patterns.append({
                "rule": "corroboration", "trigger": "amcache_without_prefetch",
                "severity": "HIGH",
                "message": ("Execution in Amcache without Prefetch corroboration — "
                            "possible anti-forensics or Prefetch disabled"),
            })
    # MFT present but EVTX outside time window
    if "analyzemft" in tools and "evtx" in tools:
        ts_m = _parse_ts(tools["analyzemft"].get("timestamp", ""))
        ts_e = _parse_ts(tools["evtx"].get("timestamp", ""))
        if ts_m and ts_e and _delta_s(ts_m, ts_e) > CONFIG["proximity_confirm_seconds"]:
            patterns.append({
                "rule": "corroboration", "trigger": "mft_without_evtx",
                "severity": "MEDIUM",
                "message": (f"MFT shows file activity but EVTX has no matching event "
                            f"within {CONFIG['proximity_confirm_seconds']}s window — "
                            "possible gap in event logging"),
            })
    return patterns

# ---------------------------------------------------------------------------
# Rule 3 – Known-Bad Pattern Detection
# ---------------------------------------------------------------------------
def _rule_known_bad(findings: list[dict]) -> list[dict]:
    """Detect known-bad patterns: single-source exec, timeline gaps, simultaneity."""
    patterns: list[dict] = []
    confs = {_tool(f): _conf(f) for f in findings}
    # 3a – Single-source execution
    if confs.get("amcache") == "CONFIRMED" and confs.get("prefetch") != "CONFIRMED":
        patterns.append({
            "rule": "known_bad", "trigger": "single_source_execution",
            "severity": "MEDIUM",
            "message": "Unconfirmed execution — single source only",
        })
    # 3b – Timeline gap keywords
    for f in findings:
        if _tool(f) != "log2timeline":
            continue
        text = _summary(f)
        if any(kw in text for kw in CONFIG["gap_keywords"]):
            patterns.append({
                "rule": "known_bad", "trigger": "timeline_gap",
                "severity": "HIGH",
                "message": "Timeline gap detected — possible log clearing",
            })
    # 3c – Suspicious simultaneity across different artifact types
    sim = CONFIG["simultaneity_seconds"]
    for i, a in enumerate(findings):
        ts_a = _parse_ts(a.get("timestamp", ""))
        if not ts_a:
            continue
        for b in findings[i + 1:]:
            if _atype(a) == _atype(b):
                continue
            ts_b = _parse_ts(b.get("timestamp", ""))
            if not ts_b:
                continue
            if _delta_s(ts_a, ts_b) < sim:
                patterns.append({
                    "rule": "known_bad", "trigger": "suspicious_simultaneity",
                    "severity": "HIGH",
                    "message": (f"Suspicious simultaneity — {_tool(a)} and {_tool(b)} "
                                f"within {sim}s across different artifact types — "
                                "possible anti-forensics"),
                })
    return patterns

# ---------------------------------------------------------------------------
# Confidence roll-up & summary
# ---------------------------------------------------------------------------
def _overall_confidence(confirmed: list, contradictions: list, suspicious: list) -> str:
    """Derive RULE_CONFIRMED, RULE_SUSPECTED, or INSUFFICIENT_DATA."""
    if contradictions or suspicious:
        return "RULE_SUSPECTED"
    if confirmed:
        return "RULE_CONFIRMED"
    return "INSUFFICIENT_DATA"

def _build_summary(confirmed: list, contradictions: list, suspicious: list) -> str:
    """One plain-English sentence summarising correlation results."""
    parts: list[str] = []
    if confirmed:
        parts.append(f"{len(confirmed)} corroborated pair(s)")
    if contradictions:
        parts.append(f"{len(contradictions)} contradiction(s)")
    if suspicious:
        parts.append(f"{len(suspicious)} suspicious pattern(s)")
    if not parts:
        return "No cross-correlation data available — insufficient findings."
    return "Cross-correlation found " + ", ".join(parts) + "."

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def correlate(findings: list[dict]) -> dict[str, Any]:
    """Run all correlation rules on a list of Finding dicts.

    Parameters
    ----------
    findings : list[dict]
        Finding dicts from tagger (keys: tool_name, timestamp,
        confidence_class, evidence_summary).

    Returns
    -------
    dict  –  CorrelationReport with keys: confirmed_pairs, contradictions,
             suspicious_patterns, correlation_confidence, summary, dead_end.
    """
    _dead_end_msg = ("Fewer than 2 tool sources returned usable findings — "
                     "acquire additional artifacts before drawing cross-source conclusions.")
    if not findings:
        return {
            "confirmed_pairs": [], "contradictions": [],
            "suspicious_patterns": [],
            "correlation_confidence": "INSUFFICIENT_DATA",
            "summary": "No findings provided for correlation.",
            "dead_end": _dead_end_msg,
        }
    confirmed, contradictions = _rule_timestamp_proximity(findings)
    suspicious = _rule_corroboration(findings) + _rule_known_bad(findings)
    confidence = _overall_confidence(confirmed, contradictions, suspicious)
    return {
        "confirmed_pairs": confirmed,
        "contradictions": contradictions,
        "suspicious_patterns": suspicious,
        "correlation_confidence": confidence,
        "summary": _build_summary(confirmed, contradictions, suspicious),
        "dead_end": _dead_end_msg if confidence == "INSUFFICIENT_DATA" else "",
    }
