"""
agent/validators.py – CANDOR Schema Validators

Lightweight schema checks on forensic tool output AFTER tool execution
and BEFORE confidence tagging.  If validation fails, confidence is
downgraded from CONFIRMED to SUSPECTED (or UNKNOWN).

All patterns live in SCHEMAS at module top.  No external dependencies.
"""
from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Configuration – per-tool validation schemas
# ---------------------------------------------------------------------------
SCHEMAS: dict[str, dict[str, Any]] = {
    "amcache": {
        "required_patterns": {
            "sha1_hash": r"[0-9a-fA-F]{40}",
            "drive_path": r"[A-Za-z]:\\",
            "timestamp":  r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}",
        },
        "fail_confidence": "SUSPECTED",
    },
    "analyzemft": {
        "required_keywords": ["mft", "record", "inode"],
        "zero_data_pattern": r"\b0 records\b",
        "zero_data_confidence": "SUSPECTED",
        "fail_confidence": "SUSPECTED",
    },
    "evtx": {
        "required_patterns": {
            "event_id_value": r"(?i)event\s?id[:\s]+\d{1,5}",
        },
        "required_keywords_any": ["eventid", "event id", "eventcode"],
        "fail_confidence": "SUSPECTED",
    },
    "prefetch": {
        "required_keywords": [".pf"],
        "required_keywords_any_secondary": ["run count", "last run"],
        "fail_confidence": "SUSPECTED",
    },
    "log2timeline": {
        "required_patterns": {
            "timestamp": r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}",
        },
        "zero_data_pattern": r"\b0 events\b",
        "zero_data_confidence": "UNKNOWN",
        "warning_keyword": "warning",
        "warning_confidence": "SUSPECTED",
        "fail_confidence": "SUSPECTED",
    },
    "volatility3": {
        "required_keywords": ["pid"],
        "required_keywords_any_secondary": ["process", "imagefilename", "ppid", "args", "protection"],
        "fail_confidence": "SUSPECTED",
    },
}

# ---------------------------------------------------------------------------
# Per-tool validators
# ---------------------------------------------------------------------------
def _validate_amcache(output: str, schema: dict) -> tuple[bool, list[str]]:
    """Validate Amcache output for SHA1 hashes, drive paths, and timestamps."""
    failures: list[str] = []
    for name, pattern in schema["required_patterns"].items():
        if not re.search(pattern, output):
            failures.append(f"Missing required {name} pattern")
    return (len(failures) == 0, failures)


def _validate_analyzemft(output: str, schema: dict) -> tuple[bool, list[str]]:
    """Validate MFT output for record/inode keywords and non-zero data."""
    failures: list[str] = []
    ol = output.lower()
    if not any(kw in ol for kw in schema["required_keywords"]):
        failures.append("Missing MFT/record/inode keyword in output")
    zp = schema.get("zero_data_pattern")
    if zp and re.search(zp, ol):
        failures.append("Output reports 0 records — no data returned")
    return (len(failures) == 0, failures)


def _validate_evtx(output: str, schema: dict) -> tuple[bool, list[str]]:
    """Validate EVTX output for Event ID patterns and field labels."""
    failures: list[str] = []
    for name, pattern in schema["required_patterns"].items():
        if not re.search(pattern, output):
            failures.append(f"Missing required {name} pattern")
    ol = output.lower()
    kws = schema.get("required_keywords_any", [])
    if kws and not any(kw in ol for kw in kws):
        failures.append("Missing EventID/EventCode field label")
    return (len(failures) == 0, failures)


def _validate_prefetch(output: str, schema: dict) -> tuple[bool, list[str]]:
    """Validate Prefetch output for .pf references and run metadata."""
    failures: list[str] = []
    ol = output.lower()
    if not any(kw in ol for kw in schema["required_keywords"]):
        failures.append("Missing .pf file reference")
    sec = schema.get("required_keywords_any_secondary", [])
    if sec and not any(kw in ol for kw in sec):
        failures.append("Missing run count or last run time")
    return (len(failures) == 0, failures)


def _validate_log2timeline(output: str, schema: dict) -> tuple[bool, list[str]]:
    """Validate log2timeline output for timestamps, zero events, and warnings."""
    failures: list[str] = []
    for name, pattern in schema.get("required_patterns", {}).items():
        if not re.search(pattern, output):
            failures.append(f"Missing required {name} pattern")
    ol = output.lower()
    zp = schema.get("zero_data_pattern")
    if zp and re.search(zp, ol):
        failures.append("Output reports 0 events — no timeline data")
    wk = schema.get("warning_keyword")
    if wk and wk in ol:
        failures.append("Output contains warning — possible degraded run")
    return (len(failures) == 0, failures)


def _validate_volatility3(output: str, schema: dict) -> tuple[bool, list[str]]:
    """Validate Volatility3 output for PID column and plugin-specific headers."""
    failures: list[str] = []
    ol = output.lower()
    if not any(kw in ol for kw in schema["required_keywords"]):
        failures.append("Missing PID column header")
    sec = schema.get("required_keywords_any_secondary", [])
    if sec and not any(kw in ol for kw in sec):
        failures.append("Missing plugin-specific header (Process/ImageFileName/PPID/Args/Protection)")
    return (len(failures) == 0, failures)


_VALIDATORS = {
    "amcache":      _validate_amcache,
    "analyzemft":   _validate_analyzemft,
    "evtx":         _validate_evtx,
    "prefetch":     _validate_prefetch,
    "log2timeline": _validate_log2timeline,
    "volatility3":  _validate_volatility3,
}

# ---------------------------------------------------------------------------
# Confidence resolution
# ---------------------------------------------------------------------------
def _resolve_confidence(schema: dict, failures: list[str], output: str) -> str:
    """Determine suggested confidence from schema rules and failure list.

    Note: Only returns CONFIRMED, SUSPECTED, or UNKNOWN — never INFERRED.
    """
    ol = output.lower()
    # Zero-data check overrides
    zp = schema.get("zero_data_pattern")
    if zp and re.search(zp, ol):
        return schema.get("zero_data_confidence", schema["fail_confidence"])
    # Warning check (log2timeline)
    wk = schema.get("warning_keyword")
    if wk and wk in ol:
        return schema.get("warning_confidence", schema["fail_confidence"])
    if failures:
        return schema["fail_confidence"]
    return "CONFIRMED"

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def validate(tool_name: str, output: str) -> dict[str, Any]:
    """Validate forensic tool output against its expected schema.

    Parameters
    ----------
    tool_name : str
        Normalised tool name (amcache, analyzemft, evtx, prefetch, log2timeline).
    output : str
        The raw stdout from the tool execution.

    Returns
    -------
    dict – ValidationResult with keys: valid, failed_checks,
           suggested_confidence, reasoning.
    """
    name = tool_name.lower().strip()
    if name not in SCHEMAS:
        return {
            "valid": True, "failed_checks": [],
            "suggested_confidence": "INFERRED",
            "reasoning": f"No validation schema registered for tool '{name}' — confidence downgraded to INFERRED until schema is defined.",
        }
    schema = SCHEMAS[name]
    validator = _VALIDATORS[name]
    valid, failures = validator(output, schema)
    confidence = _resolve_confidence(schema, failures, output)
    if valid and confidence == "CONFIRMED":
        reasoning = f"Tool '{name}' output passed all schema checks."
    else:
        reasoning = (f"Tool '{name}' failed {len(failures)} check(s): "
                     + "; ".join(failures) + ".")
    return {
        "valid": valid,
        "failed_checks": failures,
        "suggested_confidence": confidence,
        "reasoning": reasoning,
    }
