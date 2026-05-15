"""
agent/reporter.py
-----------------
CANDOR – HTML Report Generator

Single responsibility: convert a list of Finding dicts (from tagger.py)
into a self-contained, zero-dependency HTML report and save it to disk.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_COLORS = {
    "CONFIRMED": "#238636",
    "INFERRED":  "#9e6a03",
    "SUSPECTED": "#bd561d",
    "UNKNOWN":   "#8e1519",
}

_CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
     background:#0d1117;color:#e6edf3;line-height:1.6;padding:2rem;max-width:1000px;margin:0 auto}
header{padding-bottom:1rem;margin-bottom:1.75rem;border-bottom:1px solid #30363d}
header h1{font-size:1.5rem;font-weight:700;color:#fff;letter-spacing:.01em}
header .meta{font-size:.82rem;color:#8b949e;margin-top:.3rem}
.bar{display:flex;gap:.75rem;flex-wrap:wrap;margin-bottom:1.75rem}
.chip{border:1px solid #30363d;border-radius:6px;padding:.5rem .9rem;
      background:#161b22;font-size:.82rem}
.chip .lbl{font-size:.68rem;color:#8b949e;text-transform:uppercase;
           letter-spacing:.09em;display:block;margin-bottom:.15rem}
.chip .val{font-weight:700}
.cards{display:flex;flex-direction:column;gap:.75rem}
.card{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:1rem 1.2rem}
.ch{display:flex;align-items:center;gap:.6rem;margin-bottom:.6rem}
.ch h2{font-size:.93rem;font-weight:600;color:#fff}
.badge{border-radius:4px;padding:.18rem .55rem;font-size:.7rem;font-weight:700;
       letter-spacing:.05em;text-transform:uppercase;color:#fff}
.ts{font-size:.72rem;color:#484f58;margin-left:auto}
.sec{margin-top:.5rem}
.sec .lbl{font-size:.65rem;text-transform:uppercase;letter-spacing:.1em;
          color:#8b949e;margin-bottom:.2rem}
.sec p{font-size:.82rem;color:#8b949e}
.de{margin-top:2.5rem;padding-top:1.5rem;border-top:1px solid #30363d}
.de h2{font-size:.93rem;font-weight:600;color:#fff;margin-bottom:.75rem}
.de ul{list-style:disc;padding-left:1.2rem;display:flex;flex-direction:column;gap:.35rem}
.de li{font-size:.82rem;color:#cdd9e5}
.empty{color:#8b949e;font-style:italic;font-size:.82rem}
footer{margin-top:2.5rem;font-size:.7rem;color:#484f58}
"""


def _esc(t: str) -> str:
    """HTML-escape a plain string to prevent injection in the report."""
    return str(t).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")


def _build_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Return a dict mapping each confidence class to its finding count."""
    counts = {c: 0 for c in _COLORS}
    for f in findings:
        cls = f.get("confidence_class", "UNKNOWN")
        counts[cls] = counts.get(cls, 0) + 1
    return counts


def _build_dead_ends(findings: list[dict[str, Any]]) -> list[str]:
    """Collect every dead-end string from all findings into a deduplicated flat list."""
    seen: set[str] = set()
    result: list[str] = []
    for f in findings:
        for de in f.get("dead_ends", []):
            if de not in seen:
                seen.add(de)
                result.append(de)
    return result


def _render_html(case_name: str, findings: list[dict[str, Any]],
                 summary: dict[str, int], dead_ends: list[str]) -> str:
    """Render the complete self-contained HTML document as a string."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    chips = "".join(
        f'<div class="chip">'
        f'<span class="lbl">{c}</span>'
        f'<span class="val" style="color:{_COLORS.get(c,"#8b949e")};">{n}</span>'
        f'</div>'
        for c, n in summary.items()
    )

    cards = []
    for f in findings:
        cls = f.get("confidence_class", "UNKNOWN")
        col = _COLORS.get(cls, "#8b949e")
        cards.append(
            f'<div class="card">'
            f'<div class="ch"><h2>{_esc(f.get("tool_name",""))}</h2>'
            f'<span class="badge" style="background:{col};">{_esc(cls)}</span>'
            f'<span class="ts">{_esc(f.get("timestamp",""))}</span></div>'
            f'<div class="sec"><div class="lbl">Evidence</div>'
            f'<p>{_esc(f.get("evidence_summary",""))}</p></div>'
            f'<div class="sec"><div class="lbl">Reasoning</div>'
            f'<p>{_esc(f.get("reasoning",""))}</p></div>'
            f'</div>'
        )

    de_items = (
        '<ul>' + ''.join(f'<li>{_esc(d)}</li>' for d in dead_ends) + '</ul>'
        if dead_ends else '<p class="empty">No missing evidence gaps identified.</p>'
    )

    return (
        f'<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>'
        f'<meta name="viewport" content="width=device-width,initial-scale=1.0"/>'
        f'<title>CANDOR -- {_esc(case_name)}</title>'
        f'<style>{_CSS}</style></head><body>'
        f'<header><h1>CANDOR</h1>'
        f'<div class="meta">Case: {_esc(case_name)} | {ts} | {len(findings)} finding(s)</div>'
        f'</header>'
        f'<div class="bar">{chips}</div>'
        f'<div class="cards">{"".join(cards) or "<p class=empty>No findings recorded.</p>"}</div>'
        f'<div class="de"><h2>Dead Ends / Missing Evidence</h2>{de_items}</div>'
        f'<footer>CANDOR Forensic Incident Response Agent</footer>'
        f'</body></html>'
    )


def generate_report(findings: list[dict], case_name: str, output_dir: str) -> str:
    """Generate a professional HTML incident-response report and save it to disk.

    Parameters
    ----------
    findings:
        List of Finding dicts as produced by ``tagger.py``'s ``Finding.to_dict()``.
    case_name:
        Human-readable name of the IR case used in the report header.
    output_dir:
        Directory where the HTML file will be written; created if absent.

    Returns
    -------
    str
        Absolute path to the saved HTML file.
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    safe = case_name.replace(" ", "_").replace("/", "-")
    ts   = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = out_path / f"candor_{safe}_{ts}.html"
    path.write_text(
        _render_html(case_name, findings, _build_summary(findings), _build_dead_ends(findings)),
        encoding="utf-8",
    )
    return str(path.resolve())


# ---------------------------------------------------------------------------
# Self-test  (python agent/reporter.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _samples = [
        {"confidence_class": "CONFIRMED",  "tool_name": "volatility3",
         "timestamp": "2026-05-14T08:00:00Z",
         "evidence_summary": "PID 4 System, PID 88 smss.exe – clean process tree.",
         "reasoning": "Tool ran with no errors; output is directly readable.",
         "dead_ends": ["Correlate PIDs with network connections to identify C2 beacons.",
                       "Cross-reference parent PIDs against baseline image."]},
        {"confidence_class": "INFERRED",   "tool_name": "log2timeline",
         "timestamp": "2026-05-14T08:05:00Z",
         "evidence_summary": "SHA256: a3f1... entropy: 7.92 offset: 0x1A4C",
         "reasoning": "Output contains forensic indicator 'entropy'; requires correlation.",
         "dead_ends": ["Entropy alone doesn't confirm encryption – acquire packed sample."]},
        {"confidence_class": "SUSPECTED",  "tool_name": "fls",
         "timestamp": "2026-05-14T08:10:00Z",
         "evidence_summary": "r/r 12345: suspicious.exe",
         "reasoning": "Output returned alongside error; partial or degraded run suspected.",
         "dead_ends": ["Inode table truncated – attempt carving with photorec.",
                       "Verify filesystem journal for overwritten entries."]},
    ]
    print(generate_report(_samples, "Demo IR Case", "reports"))
