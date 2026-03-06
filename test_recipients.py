#!/usr/bin/env python3
"""Test script to verify recipient extraction from saved search config."""

from splunk_engine import load_config, SplunkClient
from urllib.parse import urlparse

cfg = load_config()
# servers is a list; take the first one or format as URL
server = cfg.servers[0] if cfg.servers else "https://127.0.0.1:8089"
base_url = server if server.startswith("http") else f"https://{server}:8089"
client = SplunkClient(base_url, cfg.username, cfg.password)

print("Testing recipient extraction from saved search config via REST API...\n")

# Get list of saved searches
ids, names, email_flags = client.list_saved_searches("search")

print(f"Found {len(ids)} saved searches\n")

# Test recipient extraction for each search
recipients_by_report = {}
for i, (search_id, search_name) in enumerate(zip(ids, names)):
    try:
        # Extract path from full URL
        parsed = urlparse(search_id)
        path = parsed.path
        
        # Query the saved search via REST API
        meta = client._get(path)
        entry = meta.get("entry", [{}])[0]
        content = entry.get("content", {})
        
        # Get action.email.to field
        rcpt = content.get("action.email.to", "").strip()
        
        print(f"[{i+1}] Report: {search_name}")
        print(f"    Email config: {repr(rcpt)}")
        
        if rcpt:
            parts = [p.strip() for p in rcpt.replace(';', ',').split(',') if p.strip()]
            print(f"    Parsed recipients: {parts}")
            recipients_by_report[search_name] = parts
        else:
            print(f"    Parsed recipients: (none configured)")
        
        print()
    except Exception as e:
        print(f"[{i+1}] Report: {search_name}")
        print(f"    ERROR: {e}")
        print()

print("\n--- Summary ---")
print(f"Reports with recipients: {len(recipients_by_report)}")
for name, rcpts in recipients_by_report.items():
    print(f"  {name}: {', '.join(rcpts)}")
