# Security Notes: Splunk Token Handling

## Overview
This tool supports Splunk REST API authentication with bearer tokens and avoids storing decrypted tokens on disk.

Supported token storage modes:
- `token_storage = splunk_secret` (recommended)
- `token_storage = plain` (development only)

`pass4SymmKey` is not used by this tool. It is for Splunk component trust, not client REST token handling.

## Recommended Mode (`splunk_secret`)
Set in `[splunk]`:

```ini
auth_mode = token
token_storage = splunk_secret
token_encrypted = $7$...
splunk_cli_path = C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe
```

At runtime, the app decrypts `token_encrypted` by executing local Splunk UF CLI:

```powershell
splunk.exe show-decrypted --value "$7$..."
```

Decryption works only on hosts with the matching local `splunk.secret`.

## Admin Commands
Generate encrypted token:

```powershell
splunk.exe show-encrypted --value "<token>"
```

Decrypt for troubleshooting (local host only):

```powershell
splunk.exe show-decrypted --value "$7$..."
```

## Runtime Behavior
- Token is decrypted in memory only.
- REST calls use:
  - `Authorization: Bearer <token>`
- Token value is never logged.
- Authorization header is never logged.

## Validation Command
Use:

```powershell
python tool.py --test-auth
```

This command:
1. Loads config
2. Decrypts token if needed
3. Calls `/services/server/info`
4. Prints success/failure without printing token

