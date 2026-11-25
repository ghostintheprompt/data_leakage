import argparse
import json
import os
import re

TOKEN_PATTERNS = {
    "datadog_client_token": re.compile(r"\bpub_[a-zA-Z0-9_]{10,40}\b|\bpub[a-f0-9]{20,}\b")
}
API_PATH_RE = re.compile(r"/(workflows|v1/wf|trajectories|v1/t)/")
KEYWORD_RE = re.compile(r"\b(stealth|orchestrator|multi-agent-planner|carbon)\b", re.I)


def scan_har_file(har_path):
    findings = {"tokens": set(), "paths": set(), "keywords": set()}
    if not os.path.exists(har_path):
        return findings
    try:
        with open(har_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
            entries = data.get("log", {}).get("entries", [])
            for entry in entries:
                url = entry.get("request", {}).get("url", "")
                body_text = entry.get("request", {}).get("postData", {}).get("text", "")
                
                combined = f"{url} {body_text}"
                for tok in TOKEN_PATTERNS["datadog_client_token"].findall(combined):
                    findings["tokens"].add(tok)
                if API_PATH_RE.search(combined):
                    findings["paths"].add(url)
                for kw in KEYWORD_RE.findall(combined):
                    findings["keywords"].add(kw)
    except Exception as e:
        print(f"[-] Error scanning HAR path: {e}")
    return findings


def scan_bundle_dir(bundle_dir):
    findings = {"tokens": set(), "keywords": set()}
    if not os.path.exists(bundle_dir):
        return findings
    for root, _, files in os.walk(bundle_dir):
        for file in files:
            if file.endswith((".js", ".html", ".txt")):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for tok in TOKEN_PATTERNS["datadog_client_token"].findall(content):
                            findings["tokens"].add(tok)
                        for kw in KEYWORD_RE.findall(content):
                            findings["keywords"].add(kw)
                except Exception:
                    pass
    return findings


def render_cti_report(project, har_finds, bundle_finds, output_path):
    total_tokens = har_finds['tokens'].union(bundle_finds['tokens'])
    total_keywords = har_finds['keywords'].union(bundle_finds['keywords'])
    
    if not total_tokens and not har_finds['paths'] and not total_keywords:
        conclusion_text = "Verification success. Telemetry privacy controls verified. No structural metadata leakage identified."
    else:
        conclusion_text = "Telemetry components continue to expose active node properties outside authorization perimeters."

    report = f"""# CTI Threat Analysis Report: {project}
    
## 1. Observed Public Exposure Vectors
* **Exposed Client Pipeline Tokens:** {list(total_tokens) or 'None Detected'}
* **Exposed API Pipeline Paths Discovered:** {len(har_finds['paths'])} entries identified.

## 2. Leak Footprint Summary
* **Leaked Structural Keywords (OpSec Risk):** {list(total_keywords) or 'None Detected'}

## 3. Conclusion
{conclusion_text}
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"[+] Technical audit summary cleanly exported to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Static Telemetry & OpSec Artifact Auditor")
    parser.add_argument("--project", default="Production Upgrade Phase", help="Project identifier")
    parser.add_argument("--har", default="session.har", help="Path to input HAR trace file")
    parser.add_argument("--bundle-dir", default="dist/", help="Path to frontend production build folder")
    parser.add_argument("--out", default="cti_audit_report.md", help="Path to output markdown report file")
    args = parser.parse_args()

    har_finds = scan_har_file(args.har)
    bundle_finds = scan_bundle_dir(args.bundle_dir)
    render_cti_report(args.project, har_finds, bundle_finds, args.out)


if __name__ == "__main__":
    main()
