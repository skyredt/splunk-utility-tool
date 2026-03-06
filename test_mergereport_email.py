#!/usr/bin/env python3
"""Test MergeReport recipient extraction."""

from splunk_engine import load_config, SplunkClient
from urllib.parse import urlparse

cfg = load_config()
server = cfg.servers[0] if cfg.servers else "https://127.0.0.1:8089"
base_url = server if server.startswith("http") else f"https://{server}:8089"
client = SplunkClient(base_url, cfg.username, cfg.password)

print("Testing MergeReport recipient extraction...\n")

# Get saved searches
ids, names, _ = client.list_saved_searches("search")

# Test recipient extraction for TestReport
for i, name in enumerate(names):
    if "TestReport" in name:
        report_id_url = ids[i]
        try:
            parsed = urlparse(report_id_url)
            path = parsed.path
            
            meta = client._get(path)
            entry = meta.get("entry", [{}])[0]
            content = entry.get("content", {})
            
            # Check both email methods
            native_email = content.get("action.email.to", "").strip()
            mergereport_email = content.get("action.mergeReport.param.To", "").strip()
            
            print(f"Report: {name}")
            print(f"  action.email.to: {repr(native_email)}")
            print(f"  action.mergeReport.param.To: {repr(mergereport_email)}")
            
            # Apply logic
            rcpt = native_email or mergereport_email
            if rcpt:
                parts = [p.strip() for p in rcpt.replace(';', ',').split(',') if p.strip()]
                print(f"  [OK] Extracted recipients: {parts}")
            else:
                print(f"  [NO] No recipients found")
        except Exception as e:
            print(f"  [ERROR] {e}")
        break
