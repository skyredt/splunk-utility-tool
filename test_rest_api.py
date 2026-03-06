#!/usr/bin/env python3
"""Test script to inspect REST API response for email fields."""

from splunk_engine import load_config, SplunkClient
import json

cfg = load_config()
# servers is a list; take the first one or format as URL
server = cfg.servers[0] if cfg.servers else "https://127.0.0.1:8089"
base_url = server if server.startswith("http") else f"https://{server}:8089"
client = SplunkClient(base_url, cfg.username, cfg.password)

print("Querying saved searches from /servicesNS/skyred5/search/saved/searches...")
resp = client._get('/servicesNS/skyred5/search/saved/searches')

if 'entry' in resp and resp['entry']:
    print(f"\nFound {len(resp['entry'])} saved searches\n")
    for i, entry in enumerate(resp['entry'][:2]):  # First 2 searches
        title = entry.get('title', 'Unknown')
        content = entry.get('content', {})
        print(f"[{i+1}] Title: {title}")
        print(f"    ID: {entry.get('id', 'N/A')}")
        
        # Check for email-related fields
        email_fields = {}
        for k, v in content.items():
            if 'email' in k.lower() or 'action' in k.lower() or 'alert' in k.lower():
                email_fields[k] = v
        
        if email_fields:
            print("    Email/Action fields found:")
            for k, v in sorted(email_fields.items()):
                print(f"      {k}: {repr(v)}")
        else:
            print("    No email/action fields found in response")
        
        print()
else:
    print("No saved searches found in response")
