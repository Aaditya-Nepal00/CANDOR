"""
agent/loop.py
-------------
CANDOR – Autonomous Forensic Agent Loop

Orchestrates SIFT forensic tools, classifies results via EpistemicTagger,
applies a self-correction loop for low-confidence findings, then writes an
HTML report and a JSON execution log.

CLI:
    python agent/loop.py --case /cases/001 --output /cases/001/out

Programmatic:
    from agent.loop import run_case
    report_path = run_case("/cases/001")
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure we can import from 'agent' when run as a script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.tagger import EpistemicTagger
from agent.reporter import generate_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("candor.loop")

_RETRY_CLASSES = {"UNKNOWN", "SUSPECTED"}
_MAX_RETRIES = 3

# Tool definitions – {case_dir} is substituted at runtime; no hardcoded paths.
_TOOLS: list[tuple[str, list[str]]] = [
    ("amcache",      ["amcache.py", "-f", "{case_dir}"]),
    ("analyzemft",   ["analyzemft", "-f", "{case_dir}/$MFT", "-o", "csv"]),
    ("log2timeline", ["log2timeline.py", "--storage-file",
                      "{case_dir}/timeline.plaso", "{case_dir}"]),
]

_RETRY_VARIANTS: dict[str, list[list[str]]] = {
    "amcache": [
        ["amcache.py", "-f", "{case_dir}", "--verbose"],
        ["amcache.py", "-f", "{case_dir}", "--all"],
        ["amcache.py", "-f", "{case_dir}", "--debug"],
    ],
    "analyzemft": [
        ["analyzemft", "-f", "{case_dir}/$MFT", "-o", "csv", "--debug"],
        ["analyzemft", "-f", "{case_dir}/$MFT", "-o", "body"],
        ["analyzemft", "-f", "{case_dir}/$MFT"],
    ],
    "log2timeline": [
        ["log2timeline.py", "--logfile", "{case_dir}/l2t.log",
         "--storage-file", "{case_dir}/timeline.plaso", "{case_dir}"],
        ["log2timeline.py", "--workers", "1",
         "--storage-file", "{case_dir}/timeline.plaso", "{case_dir}"],
        ["log2timeline.py", "--single_process",
         "--storage-file", "{case_dir}/timeline.plaso", "{case_dir}"],
    ],
}


def _attempt_tool(tool_name: str, cmd: list[str], attempt: int) -> dict[str, Any]:
    """Run one forensic tool subprocess; return a raw result dict."""
    ts = datetime.now(timezone.utc).isoformat()
    log.info("[%s] attempt %d  cmd=%s", tool_name, attempt, cmd)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {"tool": tool_name, "output": r.stdout, "error": r.stderr,
                "timestamp": ts, "cmd": cmd, "attempt": attempt, "returncode": r.returncode}
    except FileNotFoundError:
        msg = f"Tool not found on PATH: {cmd[0]!r}"
        log.warning("[%s] %s", tool_name, msg)
    except subprocess.TimeoutExpired:
        msg = "Tool timed out after 300 s"
        log.warning("[%s] %s", tool_name, msg)
    return {"tool": tool_name, "output": "", "error": msg,
            "timestamp": ts, "cmd": cmd, "attempt": attempt, "returncode": -1}


def _should_retry(finding: dict[str, Any]) -> bool:
    """Return True when a finding's confidence class warrants a retry."""
    return finding.get("confidence_class") in _RETRY_CLASSES


def _log_execution(log_path: str, entries: list[dict[str, Any]]) -> None:
    """Persist the structured JSON execution log to *log_path*."""
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"generated": datetime.now(timezone.utc).isoformat(),
                    "entry_count": len(entries), "entries": entries}, indent=2),
        encoding="utf-8",
    )
    log.info("Execution log saved -> %s", path)


def _substitute(cmd: list[str], case_dir: str) -> list[str]:
    """Replace {case_dir} placeholder in every command token."""
    return [t.replace("{case_dir}", case_dir) for t in cmd]


def _print_summary(findings: list[dict], report: str, logf: str, iters: int) -> None:
    """Print a concise terminal summary of the CANDOR run."""
    counts: dict[str, int] = {}
    for f in findings:
        cls = f.get("confidence_class", "UNKNOWN")
        counts[cls] = counts.get(cls, 0) + 1
    w = 54
    print(f"\n{'=' * w}")
    print("  CANDOR  -  Forensic Run Summary")
    print(f"{'=' * w}")
    print(f"  Total findings   : {len(findings)}")
    print(f"  Tool executions  : {iters}")
    for cls, sym in [("CONFIRMED", "[+]"), ("INFERRED", "[~]"),
                     ("SUSPECTED", "[?]"), ("UNKNOWN", "[-]")]:
        print(f"  {sym} {cls:<12} : {counts.get(cls, 0)}")
    print(f"{'-' * w}")
    print(f"  Report  -> {report}")
    print(f"  Log     -> {logf}")
    print(f"{'=' * w}\n")


def run_case(case_dir: str, max_iterations: int = 10, output_dir: str | None = None) -> str:
    """Run the full CANDOR forensic loop against *case_dir*.

    Parameters
    ----------
    case_dir:        Path to the case evidence directory.
    max_iterations:  Hard cap on total tool executions (initial + retries).
    output_dir:      Destination for the HTML report and logs;
                     defaults to ``<case_dir>/candor_out``.

    Returns
    -------
    str – absolute path to the generated HTML report.
    """
    case_path = Path(case_dir).resolve()
    if not case_path.exists():
        raise FileNotFoundError(f"Case directory not found: {case_path}")

    out_path  = Path(output_dir).resolve() if output_dir else case_path / "candor_out"
    logs_path = out_path / "logs"

    tagger: EpistemicTagger = EpistemicTagger()
    all_findings: list[dict[str, Any]] = []
    exec_log:     list[dict[str, Any]] = []
    iteration = 0

    log.info("=== CANDOR run  case=%s  max_iterations=%d ===", case_path, max_iterations)

    for tool_name, base_cmd in _TOOLS:
        if iteration >= max_iterations:
            log.warning("max_iterations=%d reached; skipping %s", max_iterations, tool_name)
            break

        raw     = _attempt_tool(tool_name, _substitute(base_cmd, str(case_path)), attempt=1)
        iteration += 1
        finding = tagger.tag(raw).to_dict()
        all_findings.append(finding)
        exec_log.append({**raw, "finding": finding})

        variants    = _RETRY_VARIANTS.get(tool_name, [])
        retry_count = 0

        while (
            _should_retry(finding)
            and retry_count < _MAX_RETRIES
            and iteration < max_iterations
            and retry_count < len(variants)
        ):
            retry_count += 1
            log.info("[%s] confidence=%s -> retry %d/%d",
                     tool_name, finding["confidence_class"], retry_count, _MAX_RETRIES)
            raw      = _attempt_tool(
                tool_name, _substitute(variants[retry_count - 1], str(case_path)),
                attempt=retry_count + 1,
            )
            iteration += 1
            finding   = tagger.tag(raw).to_dict()
            all_findings.append(finding)
            exec_log.append({**raw, "finding": finding})

    ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_file = str(logs_path / f"execution_{ts}.json")
    _log_execution(log_file, exec_log)

    report_path = generate_report(all_findings, case_path.name, str(out_path))
    _print_summary(all_findings, report_path, log_file, iteration)
    return report_path


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="candor-loop",
        description="CANDOR – autonomous forensic agent loop",
    )
    p.add_argument("--case",           required=True,  metavar="PATH",
                   help="Path to the case evidence directory.")
    p.add_argument("--max-iterations", type=int, default=10, metavar="N",
                   help="Hard cap on total tool executions including retries (default: 10).")
    p.add_argument("--output",         default=None,   metavar="PATH",
                   help="Output directory for report and logs (default: <case>/candor_out).")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    try:
        run_case(case_dir=args.case, max_iterations=args.max_iterations, output_dir=args.output)
    except FileNotFoundError as exc:
        log.error("%s", exc)
        sys.exit(1)
