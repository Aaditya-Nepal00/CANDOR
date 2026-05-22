"""
mcp_server/server.py
--------------------
CANDOR – MCP Server for SIFT Forensic Tools

A real Model Context Protocol server (stdio transport) that exposes
SANS SIFT forensic utilities as typed MCP tools.  Designed for
integration with Claude Code via ``claude mcp add``.

Server : candor-sift  v1.0.0
Transport : stdio
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Graceful SDK import
# ---------------------------------------------------------------------------

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print(
        "ERROR: MCP Python SDK not installed.\n"
        "Run:  pip install 'mcp[cli]'",
        file=sys.stderr,
    )
    sys.exit(1)

# Ensure the agent package is importable regardless of cwd
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from agent.tagger import EpistemicTagger
    from agent.reporter import generate_report
    from agent.correlator import correlate as correlate_findings_impl
    from agent.validators import validate as validate_output_impl
except ImportError as exc:
    print(f"WARNING: agent modules unavailable ({exc})", file=sys.stderr)
    EpistemicTagger = None  # type: ignore[assignment,misc]
    generate_report = None  # type: ignore[assignment]
    correlate_findings_impl = None  # type: ignore[assignment]
    validate_output_impl = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Server instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="candor-sift",
    instructions=(
        "CANDOR SIFT Forensic MCP Server v1.0.0 – "
        "Exposes SANS SIFT forensic tools as typed MCP tools "
        "for incident response investigations."
    ),
    json_response=True,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256(filepath: str) -> str | None:
    """Return hex SHA-256 of *filepath*, or None if unreadable."""
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _hash_directory(dirpath: str, pattern: str = "*.pf") -> str | None:
    """Composite SHA-256 over all files matching *pattern* inside *dirpath*.

    Iterates files in sorted order for determinism.  Returns None if the
    directory does not exist or contains no matching files.
    """
    d = Path(dirpath)
    if not d.is_dir():
        return None
    files = sorted(f for f in d.glob(pattern) if f.is_file())
    if not files:
        return None
    outer = hashlib.sha256()
    any_hashed = False
    for f in files:
        h = _sha256(str(f))
        if h:
            outer.update(f"{f.relative_to(d)}:{h}\n".encode())
            any_hashed = True
    return outer.hexdigest() if any_hashed else None


def _ts() -> str:
    """ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def _run(cmd: list[str], tool_name: str, evidence_file: str | None = None) -> dict[str, Any]:
    """Execute a read-only subprocess and return a structured result dict.

    If *evidence_file* is given its SHA-256 is recorded before and after
    execution to prove the evidence was not modified.
    """
    result: dict[str, Any] = {
        "tool": tool_name,
        "output": "",
        "error": None,
        "timestamp": _ts(),
    }

    hash_before = _sha256(evidence_file) if evidence_file else None
    result["hash_before"] = hash_before

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
        result["output"] = proc.stdout
        result["error"] = proc.stderr or None
    except FileNotFoundError:
        result["error"] = f"Tool binary not found on PATH: {cmd[0]!r}"
    except subprocess.TimeoutExpired:
        result["error"] = f"Tool '{tool_name}' timed out after 600 s"
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"Unexpected error: {exc}"

    hash_after = _sha256(evidence_file) if evidence_file else None
    result["hash_after"] = hash_after

    return result

# ---------------------------------------------------------------------------
# Tool 1 – Amcache
# ---------------------------------------------------------------------------

@mcp.tool()
def get_amcache(case_dir: str) -> dict[str, Any]:
    """Parse the Amcache.hve registry hive for evidence of program execution.

    Runs ``amcache.py -t <case_dir>/Amcache.hve`` and returns structured
    JSON with stdout, stderr, timestamps, and integrity hashes.
    """
    evidence = os.path.join(case_dir, "Amcache.hve")
    cmd = ["amcache.py", "-t", evidence]
    return _run(cmd, "amcache", evidence_file=evidence)

# ---------------------------------------------------------------------------
# Tool 2 – MFT
# ---------------------------------------------------------------------------

@mcp.tool()
def get_mft(case_dir: str) -> dict[str, Any]:
    """Analyse the NTFS Master File Table ($MFT) and return CSV output.

    Runs ``analyzemft -f <case_dir>/$MFT -o csv`` and returns structured
    JSON with findings.
    """
    evidence = os.path.join(case_dir, "$MFT")
    cmd = ["analyzemft", "-f", evidence, "-o", "csv"]
    return _run(cmd, "analyzemft", evidence_file=evidence)

# ---------------------------------------------------------------------------
# Tool 3 – Timeline (log2timeline / plaso)
# ---------------------------------------------------------------------------

@mcp.tool()
def get_timeline(case_dir: str) -> dict[str, Any]:
    """Generate a super-timeline of filesystem and artifact events.

    Runs ``log2timeline.py`` against the case directory and returns
    structured JSON with findings.
    """
    storage = os.path.join(case_dir, "timeline.plaso")
    cmd = ["log2timeline.py", "--storage-file", storage, case_dir]

    def _timed_hash() -> tuple[str | None, str | None]:
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                return ex.submit(_hash_directory, case_dir, "**/*").result(timeout=30), None
        except concurrent.futures.TimeoutError:
            return None, "Directory hash timed out after 30 s; integrity verification skipped."

    hash_before, hash_note = _timed_hash()
    result = _run(cmd, "log2timeline")
    hash_after, note2 = _timed_hash()

    result["hash_before"] = hash_before
    result["hash_after"] = hash_after
    if hash_note or note2:
        note = hash_note or note2
        result["error"] = f"{result['error']}; {note}" if result.get("error") else note
    return result

# ---------------------------------------------------------------------------
# Tool 4 – Prefetch
# ---------------------------------------------------------------------------

@mcp.tool()
def get_prefetch(case_dir: str) -> dict[str, Any]:
    """Parse Windows Prefetch files for program-execution artefacts.

    Runs ``PECmd.py`` against ``<case_dir>/Windows/Prefetch`` and returns
    structured JSON with findings.
    """
    prefetch_dir = os.path.join(case_dir, "Windows", "Prefetch")
    cmd = ["PECmd.py", "-d", prefetch_dir]
    hash_before = _hash_directory(prefetch_dir)
    result = _run(cmd, "prefetch")
    result["hash_before"] = hash_before
    result["hash_after"] = _hash_directory(prefetch_dir)
    return result

# ---------------------------------------------------------------------------
# Tool 5 – Windows Event Logs (EVTX)
# ---------------------------------------------------------------------------

@mcp.tool()
def get_evtx(case_dir: str, log_name: str = "Security") -> dict[str, Any]:
    """Parse a Windows Event Log (.evtx) file.

    Runs ``EvtxECmd`` against the specified log inside
    ``<case_dir>/Windows/System32/winevt/Logs/`` and returns structured
    JSON with findings.
    """
    evtx_file = os.path.join(
        case_dir, "Windows", "System32", "winevt", "Logs", f"{log_name}.evtx",
    )
    cmd = ["EvtxECmd", "-f", evtx_file]
    return _run(cmd, "evtx", evidence_file=evtx_file)

# ---------------------------------------------------------------------------
# Tool 6 – Epistemic Tagger
# ---------------------------------------------------------------------------

@mcp.tool()
def tag_finding(tool_result: dict[str, Any]) -> dict[str, Any]:
    """Classify a forensic tool result into an epistemic confidence class.

    Calls the ``EpistemicTagger`` from ``agent/tagger.py`` and returns
    the full Finding dict with confidence class, reasoning, and dead ends.
    """
    if EpistemicTagger is None:
        return {
            "tool": "tag_finding",
            "output": None,
            "error": "agent.tagger module is not available",
            "timestamp": _ts(),
        }
    try:
        tagger = EpistemicTagger()
        finding = tagger.tag(tool_result)
        return finding.to_dict()
    except Exception as exc:  # noqa: BLE001
        return {
            "tool": "tag_finding",
            "output": None,
            "error": str(exc),
            "timestamp": _ts(),
        }

# ---------------------------------------------------------------------------
# Tool 7 – Report Generator
# ---------------------------------------------------------------------------

@mcp.tool()
def generate_candor_report(
    findings: list[dict[str, Any]],
    case_name: str,
    output_dir: str,
) -> str:
    """Generate a professional HTML incident-response report.

    Calls ``generate_report`` from ``agent/reporter.py`` and returns
    the absolute path to the saved HTML file.
    """
    if generate_report is None:
        return json.dumps({
            "tool": "generate_candor_report",
            "output": None,
            "error": "agent.reporter module is not available",
            "timestamp": _ts(),
        })
    try:
        path = generate_report(
            findings=findings,
            case_name=case_name,
            output_dir=output_dir,
        )
        return path
    except Exception as exc:  # noqa: BLE001
        return json.dumps({
            "tool": "generate_candor_report",
            "output": None,
            "error": str(exc),
            "timestamp": _ts(),
        })

# ---------------------------------------------------------------------------
# Tool 8 – Cross-Correlation Engine
# ---------------------------------------------------------------------------

@mcp.tool()
def correlate_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Run rule-based cross-correlation on a list of tagged findings.

    Calls ``correlate()`` from ``agent/correlator.py`` and returns a
    CorrelationReport dict containing confirmed pairs, contradictions,
    suspicious patterns, and an overall confidence rating.

    Must be called AFTER all findings have been tagged via ``tag_finding()``
    and BEFORE writing any narrative or generating the final report.
    """
    if correlate_findings_impl is None:
        return {
            "tool": "correlate_findings",
            "output": None,
            "error": "agent.correlator module is not available",
            "timestamp": _ts(),
        }
    try:
        return correlate_findings_impl(findings)
    except Exception as exc:  # noqa: BLE001
        return {
            "tool": "correlate_findings",
            "output": None,
            "error": str(exc),
            "timestamp": _ts(),
        }


# ---------------------------------------------------------------------------
# Tool 9 – Output Validator
# ---------------------------------------------------------------------------

@mcp.tool()
def validate_output(tool_name: str, output: str) -> dict[str, Any]:
    """Validate a forensic tool's output against its expected schema.

    Calls ``validate()`` from ``agent/validators.py`` and returns
    the ValidationResult dict containing validity, failed checks,
    suggested confidence, and reasoning.
    """
    if validate_output_impl is None:
        return {
            "valid": False,
            "failed_checks": ["agent.validators module is not available"],
            "suggested_confidence": "UNKNOWN",
            "reasoning": "agent.validators module is not available.",
        }
    try:
        return validate_output_impl(tool_name, output)
    except Exception as exc:  # noqa: BLE001
        return {
            "valid": False,
            "failed_checks": [str(exc)],
            "suggested_confidence": "UNKNOWN",
            "reasoning": f"Unexpected error during validation: {exc}",
        }

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
