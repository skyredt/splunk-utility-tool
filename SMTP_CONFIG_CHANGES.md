# SMTP Configuration Migration to config.ini

## Overview
Migrated SMTP configuration from environment variables to `config.ini` for persistent, centralized configuration management. This matches the design pattern of mergeReport.py and makes configuration easier to manage without relying on environment variables.

## Files Modified

### 1. config.example.ini
Added `[smtp]` section with these settings:
```ini
[smtp]
enabled = true
host = 127.0.0.1
port = 25
username = 
password = 
use_tls = false
from_address = Splunk Notification <splunk-donotreply@dsta.gov.sg>
```

### 2. config.ini
Added the same `[smtp]` section to the active configuration file.

### 3. splunk_engine.py

#### Changes to SplunkConfig dataclass:
- Added SMTP configuration fields:
  - `smtp_enabled: bool`
  - `smtp_host: str`
  - `smtp_port: int`
  - `smtp_user: str`
  - `smtp_pass: str`
  - `smtp_use_tls: bool`
  - `smtp_from: str`

#### Changes to load_config() function:
- Reads `[smtp]` section from config.ini
- Parses all SMTP settings with proper type conversions
- Defaults are sensible (127.0.0.1:25, no auth, no TLS)
- Returns SplunkConfig with SMTP settings populated

#### Changes to send_ack_summary_email() function:
- New parameter: `smtp_config: Optional[dict]`
- Configuration priority (in order):
  1. Values from smtp_config dict (from config.ini)
  2. Environment variables (for backward compatibility/overrides)
  3. Defaults or auto-detected Splunk server hostname
- Uses `smtp_use_tls` instead of `smtp_tls` (consistent naming)

#### Changes to run_dispatch_multi() function:
- New parameter: `config: Optional["SplunkConfig"]`
- Builds `smtp_config_dict` from config and passes to send_ack_summary_email()

### 4. splunk_report_tk.py

#### Changes to _dispatch_worker():
- Passes `config=self.cfg` to run_dispatch_multi()

## Configuration Priority

The tool now respects this configuration priority (highest to lowest):

1. **Environment Variables** (for overrides in special cases)
   ```powershell
   $env:SPLUNK_TOOL_SMTP_HOST = "custom-server.com"
   ```

2. **config.ini [smtp] section** (primary source)
   ```ini
   [smtp]
   host = 127.0.0.1
   port = 25
   ```

3. **Defaults** (if not set in config.ini or env vars)
   - host = 127.0.0.1
   - port = 25
   - no auth
   - no TLS

4. **Auto-detection** (if env vars and config not set)
   - Uses Splunk server hostname extracted from REST API URL
   - For jump host scenarios (tool runs on different host than Splunk)

## Configuration Example

For your environment with mergeReport SMTP settings:

```ini
[smtp]
enabled = true
host = 127.0.0.1
port = 25
username = 
password = 
use_tls = false
from_address = Splunk Notification <splunk-donotreply@dsta.gov.sg>
```

This matches the mergeReport.py settings:
```python
smtpServer="127.0.0.1"
smtpPort=25
smtpLogin=False
isTls=False
smtpUsername=""
smtpPassword=""
send_from='Splunk Notification <splunk-donotreply@dsta.gov.sg>'
```

## Environment Variable Overrides (Still Supported)

For backward compatibility or special scenarios, you can still override with env vars:

```powershell
$env:SPLUNK_TOOL_SMTP_HOST = "mail.company.com"
$env:SPLUNK_TOOL_SMTP_PORT = "587"
$env:SPLUNK_TOOL_SMTP_USER = "username"
$env:SPLUNK_TOOL_SMTP_PASS = "password"
$env:SPLUNK_TOOL_SMTP_TLS = "1"
$env:SPLUNK_TOOL_MAIL_FROM = "sender@company.com"
```

These env vars override the config.ini settings if set.

## Benefits

✅ **Persistent Configuration**: Settings survive PowerShell session restarts
✅ **Centralized Management**: All tool config in one place (config.ini)
✅ **Consistency**: Matches mergeReport.py configuration pattern
✅ **Easy Deployment**: Copy config.ini with tool; no env var setup needed
✅ **Flexibility**: Still support env var overrides for special cases
✅ **Jump Host Ready**: Auto-detects Splunk server for SMTP relay

## Testing

1. Tool reads config from [smtp] section on startup
2. ACK email uses configured SMTP settings
3. Environment variables override config.ini if set
4. If all else fails, uses auto-detected Splunk server hostname
