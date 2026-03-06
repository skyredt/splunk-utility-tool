#!/usr/bin/env python3
"""
Simulate the dispatch flow to verify recipients are extracted correctly.
"""
from splunk_engine import load_config, SplunkClient, RegenContext, get_sgt_now
from datetime import datetime, timedelta
from urllib.parse import urlparse

cfg = load_config()
server = cfg.servers[0] if cfg.servers else "https://127.0.0.1:8089"
base_url = server if server.startswith("http") else f"https://{server}:8089"
client = SplunkClient(base_url, cfg.username, cfg.password)

print("Simulating RegenContext creation with recipient extraction...\n")

# Create a RegenContext like run_dispatch_multi() does
regen_context = RegenContext(
    report_names=["[Splunk10] TestReport"],
    app="search",
    owner="skyred5",
    operator="testuser",
    hostname="TEST-PC",
    start_time_sgt=get_sgt_now(),
    end_time_sgt=None,
    slicing_enabled=False,
    slice_count=0,
    frequency="Daily",
    earliest_configured="2026-02-12",
    latest_configured="2026-02-14",
    recipients=[],
)

# Get saved searches
ids, names, _ = client.list_saved_searches("search")
print(f"Found {len(ids)} saved searches in 'search' app\n")

# Simulate recipient extraction for the TestReport
test_report_index = None
for i, name in enumerate(names):
    if "TestReport" in name:
        test_report_index = i
        break

if test_report_index is not None:
    report_id_url = ids[test_report_index]
    print(f"Found TestReport at index {test_report_index}")
    print(f"Report ID URL: {report_id_url}\n")
    
    try:
        # Extract path and query
        parsed = urlparse(report_id_url)
        path = parsed.path
        print(f"Extracted path: {path}\n")
        
        # Query the saved search
        meta = client._get(path)
        entry = meta.get("entry", [{}])[0]
        content = entry.get("content", {})
        
        # Get recipient
        rcpt = content.get("action.email.to", "").strip()
        print(f"action.email.to: {repr(rcpt)}\n")
        
        if rcpt:
            parts = [p.strip() for p in rcpt.replace(';', ',').split(',') if p.strip()]
            regen_context.recipients.extend(parts)
            print(f"[OK] Successfully extracted {len(parts)} recipient(s): {parts}\n")
        else:
            print("[NO] No recipients found in action.email.to field\n")
    except Exception as e:
        print(f"[ERROR] Error extracting recipients: {e}\n")
else:
    print("[NO] TestReport not found in saved searches\n")

# Display final context
print("--- Final RegenContext ---")
print(f"Report names: {regen_context.report_names}")
print(f"Recipients: {regen_context.recipients}")
print(f"Start time (SGT): {regen_context.start_time_sgt}")
