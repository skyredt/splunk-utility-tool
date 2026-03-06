#!/usr/bin/env python3
"""Test SMTP host extraction from Splunk server URL."""

from splunk_engine import load_config, SplunkClient
from urllib.parse import urlparse

cfg = load_config()
server = cfg.servers[0] if cfg.servers else "https://127.0.0.1:8089"
base_url = server if server.startswith("http") else f"https://{server}:8089"
client = SplunkClient(base_url, cfg.username, cfg.password)

print("Testing SMTP host extraction...\n")
print(f"Client base_url: {client.base_url}")

# Extract hostname
parsed = urlparse(client.base_url)
smtp_host = parsed.hostname or "127.0.0.1"
smtp_port = 25

print(f"Extracted SMTP host: {smtp_host}")
print(f"SMTP port: {smtp_port}")
print(f"\nFor jump host scenario:")
print(f"  - Tool on jump host will connect to: {smtp_host}:{smtp_port}")
print(f"  - Splunk server {client.base_url} will relay email")
