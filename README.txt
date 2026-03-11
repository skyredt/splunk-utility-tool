Splunk Utility Tool v4

Files
- `main.py`: launcher and internal broker entry points
- `splunk_engine.py`: config loading, Splunk REST client, dispatch orchestration
- `splunk_report_tk.py`: Tk desktop UI
- `config.ini`: runtime configuration loaded from the executable directory only
- `config.ini.example`: recovery template and canonical formatting reference

Authentication
- v4 production supports `auth_mode = password` only.
- The tool does not use token auth, plaintext password storage, or external Splunk CLI token helpers.
- Credentials are stored through the DPAPI secret file configured in `[Credentials].secret_file`.

Config Recovery
- `config.ini` must live beside the executable or source tree root.
- If `config.ini` is missing and `config.ini.example` or `config.example.ini` exists, the tool recreates `config.ini` automatically from the template.
- If `config.ini` is valid but not in canonical layout, the tool rewrites it into canonical INI format and saves the previous file as `config.ini.bak`.
- If the config is malformed, startup fails gracefully with a line-aware error message instead of a generic hardening failure.

Canonical INI Rules
- Each section header is on its own line: `[section]`
- Each setting is on its own line: `key = value`
- Blank line between sections
- Comments stay on their own lines and are preserved when possible
- File ends with a final newline

Pilot Dispatch Defaults
- `[dispatch]` uses a 30 second active wait budget per slice
- Timeout after a valid SID becomes `PENDING`, not `FAILED`
- `[postdispatch]` performs one bounded reconciliation pass after submission
- `[email]` keeps acknowledgement email enabled by default

Hardening Errors
- `Configuration error`: missing template, malformed INI, duplicate sections/keys, or unsupported formatting
- `Security policy blocked startup`: valid config parsed, but hardening settings violate policy
- `Security configuration blocked`: baseline downgrade detected after config and policy loaded successfully

Validation
- `python -m unittest test_config_runtime_behavior.py`
- `python -m unittest test_dispatch_timeout_behavior.py`
