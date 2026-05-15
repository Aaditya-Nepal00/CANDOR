# CANDOR
## Confidence-Annotated DFIR Output with Reasoning

AI agents are bad at forensics for a specific reason: they don't distinguish between what they know and what they're guessing. Hand an LLM a disk image and ask it to investigate, and you'll get a confident, well-structured report where confirmed artifacts and hallucinated conclusions are formatted identically. A practitioner reading that report has no way to know which findings came from actual tool output and which the model invented to fill gaps. In incident response, that's not a minor annoyance — it's a liability.

CANDOR forces the issue. It wraps SANS SIFT forensic tools behind an MCP server, runs them against case evidence, and tags every single finding with one of four confidence classes before it can enter the final report. The agent cannot produce a finding without classifying it. If a tool fails, the finding says UNKNOWN. If the output needs interpretation, it says INFERRED. No finding gets to hide behind ambiguity. The output is an HTML report where green means confirmed, red means unknown, and a practitioner can tell at a glance which parts of the investigation to trust and which to dig into further.

---

## Why CANDOR Exists

The hallucination problem in forensic AI isn't hypothetical. When an LLM-based agent parses Amcache output, sees an executable name, and then writes "this binary was likely used for lateral movement," there is no way to tell whether that conclusion came from corroborating event log evidence or from the model's training data. The agent doesn't flag its own uncertainty. It presents everything with the same authoritative tone. In a discipline where investigators testify under oath about their findings, that's unacceptable.

The insight behind CANDOR is that labeling confidence matters more than improving accuracy. You can't prevent an AI from occasionally being wrong, but you can force it to show its work. If every finding carries a confidence tag — CONFIRMED when two tools agree, SUSPECTED when they contradict, UNKNOWN when a tool crashed — then a human analyst can triage the report efficiently. They spend time verifying the yellow and red items instead of re-doing the entire investigation. The problem isn't that AI makes mistakes. The problem is that AI mistakes look the same as AI conclusions.

---

## Architecture

CANDOR has four layers. Each one does exactly one thing.

### Layer 1 — The MCP Server (`mcp_server/server.py`)

This is 273 lines of Python that turns SIFT forensic tools into a Model Context Protocol server running over stdio. Instead of letting an LLM compose arbitrary shell commands (which is how most agent frameworks work and why most agent frameworks eventually destroy evidence), the server exposes seven typed functions: `get_amcache()`, `get_mft()`, `get_timeline()`, `get_prefetch()`, `get_evtx()`, `tag_finding()`, and `generate_candor_report()`. The LLM calls these functions with structured arguments. It cannot run `rm`. It cannot run `dd`. It cannot `chmod` anything. The attack surface is exactly seven read-only operations plus two processing functions.

Every forensic tool invocation goes through a `_run()` helper that does something important: it computes the SHA-256 hash of the evidence file before the tool touches it, runs the tool, then hashes the file again. If those hashes don't match, the evidence was modified and the investigation is compromised. This happens at the architecture level — it's not a prompt instruction the model can ignore. The server wraps `amcache.py`, `analyzemft`, `log2timeline.py`, `PECmd.py`, and `EvtxECmd`, all standard SIFT utilities. Each tool function takes a `case_dir` path and constructs the correct command internally. The model never sees or constructs the actual shell command.

### Layer 2 — The Epistemic Tagger (`agent/tagger.py`)

This is where confidence classification happens. The `EpistemicTagger` class (206 lines) takes raw tool output and assigns one of four classes: CONFIRMED, INFERRED, SUSPECTED, or UNKNOWN. Classification is rule-based, not LLM-based — the tagger doesn't ask the model what it thinks. It runs a deterministic ladder.

The ladder works top-down, first match wins. If the tool produced no output at all, it's UNKNOWN — doesn't matter what else happened. If the tool produced output but also wrote to stderr, it's SUSPECTED — something went partially wrong. If the output contains keywords like "warning," "truncated," "incomplete," or "0 results," it's also SUSPECTED. If the output contains forensic artifact indicators like "offset," "entropy," "sha256," or "hex dump," it's INFERRED — valid data, but it needs a human or cross-correlation to mean anything. If none of those conditions trigger, the tool ran clean with substantive output, and the finding is CONFIRMED.

Each finding becomes a `Finding` dataclass: confidence class, tool name, UTC timestamp, a 200-character evidence summary, the reasoning string explaining why the tagger chose that class, and a list of dead ends. The dead ends come from `dead_ends.json`, a configuration file that maps each confidence class to a list of actionable next steps. CONFIRMED findings get no dead ends (the empty list). UNKNOWN findings get four suggestions like "re-run the tool with verbose flags" and "verify the tool is installed." This is a config file, not hardcoded logic — you can edit the advisories without touching Python.

### Layer 3 — The Agent Brain (`agent/CLAUDE.md` + Claude Code)

CANDOR doesn't include its own LLM runtime. It's designed to run inside Claude Code, Anthropic's coding agent. The file `CLAUDE.md` (101 lines) is the system prompt that Claude Code reads when it enters the project directory. It defines CANDOR's identity, investigation sequence, self-correction rules, confidence classification criteria, dead ends protocol, reporting rules, evidence integrity requirements, and a table of red flags that a senior analyst would recognize.

The investigation sequence is an 8-step procedure executed in strict order: parse Amcache, parse Prefetch, parse MFT, parse EVTX, optionally generate a full Plaso timeline (only if steps 1–4 surfaced anomalies), tag every finding, cross-correlate all sources manually, and generate the final report. Step 5 has a gate — running `log2timeline` is expensive, so it only fires if earlier steps produced SUSPECTED findings or temporal anomalies.

Self-correction is baked into the prompt. If a finding comes back UNKNOWN on the first attempt, the agent must retry with different parameters before accepting it. Amcache contradicts Prefetch? Flag it as SUSPECTED and document the exact discrepancy. MFT shows a file but EVTX has no matching event? That's a documented dead end. Maximum three retries per tool. After three failures, classify as UNKNOWN, record the error details, and move on. The prompt explicitly forbids fabricating output — if a tool returns nothing, you report nothing.

The prompt also includes a red-flag reference table: execution in Amcache without a Prefetch `.pf` file (possible anti-forensics), diverging `$SI` and `$FN` timestamps in MFT (probable timestomping), gaps in Security.evtx with Event ID 1102 present (log clearing), and several others. These aren't suggestions — the agent is instructed to escalate confidence scrutiny when it encounters them.

### Layer 4 — The Reporter (`agent/reporter.py`)

The reporter is 186 lines of Python that turns a list of Finding dicts into a self-contained HTML file with zero external dependencies. No CDN links, no JavaScript frameworks, no network requests. The report opens in any browser, offline.

Every finding is rendered as a card with a colored confidence badge: green (#238636) for CONFIRMED, amber (#9e6a03) for INFERRED, orange (#bd561d) for SUSPECTED, red (#8e1519) for UNKNOWN. At the top of the report is a summary bar showing counts for each confidence class. At the bottom is a deduplicated Dead Ends section that aggregates every actionable next step from every finding. The styling is dark-mode, uses system fonts, and is embedded as inline CSS. The filename includes the case name and a UTC timestamp so you can run multiple investigations without overwriting previous reports.

---

## How It Works End to End

You point Claude Code at a case directory and tell it to investigate. One command — `claude` from the project root — and the agent reads `CLAUDE.md`, sees the MCP server registered in its config, and starts the investigation sequence.

First, it calls `get_amcache()` with the case directory path. The MCP server hashes the Amcache.hve file, runs `amcache.py -t` against it, hashes it again, and returns structured JSON with stdout, stderr, both hashes, and a timestamp. The agent takes that result and calls `tag_finding()`, which hands it to the EpistemicTagger. Say the Amcache parse ran clean — the tagger walks its ladder, finds no errors, no partial-result keywords, no forensic indicators requiring interpretation, and returns CONFIRMED with the reasoning "Tool 'amcache' ran successfully with no errors and returned substantive, directly readable output."

The agent moves to Prefetch. `get_prefetch()` runs `PECmd.py` against the Prefetch directory. This time, the tool writes a warning to stderr about a truncated file. The tagger sees output plus stderr, classifies it SUSPECTED, and attaches four dead-end advisories from the config file: review stderr, cross-validate with another tool, check for corruption, check version compatibility. The agent, following its self-correction rules, retries with different parameters. Maybe the second attempt also comes back SUSPECTED. After up to three retries, it accepts the best result and continues.

MFT analysis, EVTX parsing — same pattern. Each tool runs through the MCP server, gets hashed, gets tagged. After the first four steps, the agent checks whether any findings are SUSPECTED or show temporal anomalies. If yes, it calls `get_timeline()` to run `log2timeline.py` for a full super-timeline. If the case looks clean, it skips the expensive timeline generation.

Then comes cross-correlation. The agent compares timestamps across all tool outputs. Does the Amcache execution timestamp match a Prefetch last-run time? Does the MFT file-creation time align with an EVTX logon event? Matches get noted. Contradictions get flagged and downgraded. This is the step where INFERRED findings are born — no single tool showed the connection, but two tools together tell a story.

Finally, the agent calls `generate_candor_report()` with all its tagged findings, the case name, and an output directory. The reporter builds the HTML, writes it to disk, and returns the file path. The agent reports back with the path. You open the HTML file and see everything: what was found, how confident the agent is about each finding, and exactly what to investigate next for anything that isn't green.

If a tool fails entirely — binary not found, timeout after 600 seconds, permission denied — the MCP server catches the exception, returns an error string instead of stdout, and the tagger classifies it UNKNOWN. The dead ends for that finding will tell you to check your SIFT installation, verify the evidence path, and confirm the volume is mounted. The investigation doesn't stop. It documents the failure and moves on to the next tool.

---

## Getting Started

### Prerequisites

- **SANS SIFT Workstation** — download from [sans.org/tools/sift-workstation](https://www.sans.org/tools/sift-workstation). CANDOR calls SIFT tools directly; without them, every tool invocation returns UNKNOWN.
- **Claude Code** with a claude.ai Pro subscription or Anthropic API credits — this is the LLM runtime. CANDOR is a system prompt and toolset, not a standalone agent.
- **Python 3.10+**

### Installation

Clone the repository:

```bash
git clone https://github.com/your-org/candor-sift.git
cd candor-sift
```

Install the MCP Python SDK:

```bash
pip install 'mcp[cli]'
```

Register the MCP server with Claude Code:

```bash
claude mcp add candor-sift -- python mcp_server/server.py
```

Verify the server is registered:

```bash
claude mcp list
```

### Running Your First Investigation

Place your case evidence in a directory (e.g., `cases/001/`) with the expected artifacts: `Amcache.hve`, `$MFT`, Prefetch files under `Windows/Prefetch/`, event logs under `Windows/System32/winevt/Logs/`.

Launch Claude Code from the project root:

```bash
claude
```

Then give it the investigation prompt:

```
Investigate the case at cases/001/ following the CANDOR protocol. Run all forensic tools in sequence, tag every finding, cross-correlate the results, and generate the final report.
```

The agent will execute the full 8-step sequence and produce an HTML report in `cases/001/candor_out/`.

Alternatively, you can run the standalone agent loop directly (without Claude Code):

```bash
python agent/loop.py --case cases/001 --output cases/001/candor_out
```

---

## Project Structure

```
Candor-sift/
├── agent/
│   ├── CLAUDE.md          # System prompt — defines investigation behavior (101 lines)
│   ├── tagger.py          # Epistemic confidence classifier (206 lines)
│   ├── reporter.py        # HTML report generator, zero dependencies (186 lines)
│   ├── loop.py            # Standalone agent loop with retry logic (224 lines)
│   └── dead_ends.json     # Configurable next-step advisories per confidence class
├── mcp_server/
│   └── server.py          # MCP server exposing 7 tools over stdio (273 lines)
├── cases/
│   └── 001/               # Example case evidence directory
├── .gitignore
└── README.md
```

---

## The Confidence Classes

**CONFIRMED** means the tool ran without errors and the finding is directly observable in the raw output. No interpretation, no inference. Amcache.hve was parsed, and it contains an entry for `evil.exe` with a SHA1 hash, a full file path, and an execution timestamp. The Prefetch directory has a matching `.pf` file with a consistent last-run time. Two sources agree. This is as solid as it gets in forensic analysis — the data is right there in the artifact, and the tool read it correctly.

**INFERRED** means the output is valid but the conclusion requires connecting dots across sources or interpreting low-level data. The MFT shows a file created at 02:14 UTC. The Security event log shows a successful logon (Event ID 4624) at 02:13 UTC from the same workstation. Neither artifact alone proves the user created that file, but the one-minute gap and matching workstation strongly suggest it. The finding is real, but the causal link is the analyst's reasoning, not a direct artifact entry. Findings containing forensic indicators like entropy values, hex offsets, hash digests, or sector references also land here — they're meaningful data that needs context to interpret.

**SUSPECTED** means something is off. The tool produced output, but it also wrote warnings or errors to stderr. Or the output contains keywords like "truncated," "incomplete," or "0 results" that suggest the tool didn't finish cleanly. Or — and this is the important one — the finding contradicts another source. Amcache says `evil.exe` was executed at 14:32 UTC, but there's no corresponding `.pf` file in the Prefetch directory. That's not necessarily wrong (Prefetch can be disabled, or the file might have been cleaned up), but it means you can't fully trust the Amcache finding without further investigation. SUSPECTED findings always carry dead-end advisories pointing you toward what to check next.

**UNKNOWN** means the tool failed outright. It crashed, timed out after 600 seconds, returned an empty stdout, or the evidence file didn't exist. Maybe `amcache.py` isn't installed on this SIFT build. Maybe the `$MFT` is corrupt. Maybe the EVTX file header is invalid and the parser can't read it. After up to three retry attempts with different parameters, the finding stays UNKNOWN. The report still includes it — knowing that a tool failed and what it failed on is itself a finding. The dead ends for UNKNOWN tell you to check tool installation, verify permissions, confirm the evidence path, and make sure the volume is mounted.

---

## Evidence Integrity

Every time the MCP server runs a forensic tool against an evidence file, it computes the SHA-256 hash of that file before execution and again after. Both hashes are included in the tool result. If they match, the tool didn't modify the evidence. If they don't match, something wrote to the evidence file during analysis — and the investigation is compromised.

This is an architectural guardrail, not a prompt instruction. The hash computation happens in Python code inside `_run()` in `server.py`. The LLM doesn't decide whether to hash the file. It can't skip the check. It can't lie about the result. The hashes show up in the structured output that the agent processes, and the `CLAUDE.md` system prompt instructs the agent to verify hash matches and halt immediately if they differ.

Why architectural guardrails instead of just telling the model "don't modify evidence"? Because prompt instructions are suggestions. A sufficiently complex investigation, a jailbreak attempt, or just a model hallucination could lead an unrestricted agent to write a temp file into the evidence directory or pipe output back into a source artifact. By constraining the agent to seven typed functions — none of which accept write operations — and verifying file integrity with cryptographic hashes, CANDOR makes evidence modification structurally difficult rather than merely discouraged.

---

## What CANDOR Cannot Do

**It doesn't do memory forensics.** CANDOR wraps disk-based SIFT tools: Amcache, MFT, Prefetch, EVTX, and Plaso timelines. If you need Volatility for process analysis, registry hive deep-dives, or network capture parsing, you'll need to add those tools to the MCP server yourself. The architecture supports it — write a new `@mcp.tool()` function — but it's not there today.

**It trusts the underlying tools.** If `amcache.py` produces incorrect output due to a bug, CANDOR will classify that output as CONFIRMED. The tagger evaluates tool behavior (did it error? did it produce output?), not tool correctness. A clean run with wrong data still gets a green badge.

**It's not a replacement for a human analyst.** The cross-correlation step (Step 7) is performed by an LLM, which means it's subject to the same hallucination risks CANDOR was built to address. The confidence tags mitigate this — you can see exactly which findings are INFERRED vs CONFIRMED — but the final analytical judgment should come from a human who reads the report and verifies the yellow and orange items.

**Classification is coarse.** Four confidence classes cover a lot of ground. A finding with a minor stderr warning and a finding with half its output truncated both land in SUSPECTED. The reasoning string explains why, but if you need finer granularity, you'd need to extend the tagger's classification ladder.

---

## Built With

- **[MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)** (`mcp[cli]`) — Model Context Protocol server framework, stdio transport
- **Python 3.10+ standard library** — `subprocess`, `hashlib`, `json`, `dataclasses`, `pathlib`, `argparse`, `logging`, `re`, `datetime`
- **SANS SIFT Workstation tools** — `amcache.py`, `analyzemft`, `log2timeline.py`, `PECmd.py`, `EvtxECmd`
- **Claude Code** — Anthropic's coding agent, used as the LLM runtime

No other dependencies. No `requirements.txt` with 47 packages. The agent code is pure Python stdlib plus the MCP SDK.

---

## License

MIT
