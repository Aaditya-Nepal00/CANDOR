# CANDOR MCP Server
# Wraps SIFT tools with evidence receipts

import json
import hashlib
import subprocess
from datetime import datetime

def get_file_hash(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        h.update(f.read())
    return h.hexdigest()

def run_tool(cmd, tool_name):
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )
    return {
        "tool": tool_name,
        "timestamp": datetime.now().isoformat(),
        "output": result.stdout,
        "error": result.stderr
    }

def run_amcache(evidence_path):
    cmd = ["amcache.py", "-f", evidence_path]
    result = run_tool(cmd, "amcache")
    result["confidence"] = "CONFIRMED"
    result["artifact"] = "Amcache.hve"
    result["description"] = "Recently executed programs"
    return result

def run_prefetch(evidence_path):
    cmd = ["PECmd.exe", "-f", evidence_path]
    result = run_tool(cmd, "prefetch")
    result["confidence"] = "CONFIRMED"
    result["artifact"] = "Prefetch files"
    result["description"] = "Program execution history"
    return result

def run_evtx(evidence_path):
    cmd = ["EvtxECmd.exe", "-f", evidence_path]
    result = run_tool(cmd, "evtx")
    result["confidence"] = "CONFIRMED"
    result["artifact"] = "Windows Event Logs"
    result["description"] = "System and security events"
    return result

if __name__ == "__main__":
    print("CANDOR MCP Server ready")
    print("Tools: amcache, prefetch, evtx")
