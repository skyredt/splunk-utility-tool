# Splunk Utility Tool

Desktop utility for dispatching Splunk saved searches with bounded verification, date slicing, and optional acknowledgement workflows.

Created by **Gabriel (Skyredt)**  
GitHub: https://github.com/Skyredt

## Overview

Splunk Utility Tool is a Windows desktop application for operators who need a safer and more observable way to run Splunk saved searches.

It supports:
- dispatching one or many saved searches
- slicing execution windows across date ranges
- bounded retry and reconciliation behavior for uncertain dispatch results
- post-dispatch verification using native Splunk evidence
- optional MergeReport-based verification where available
- optional acknowledgement email summaries

The tool is designed to improve operational safety without treating slow or uncertain Splunk responses as immediate hard failures.

## Key Features

- Tkinter-based desktop UI
- Saved search dispatch with date slicing
- Per-slice tracking and bounded retry handling
- Local broker isolation for safer request execution
- Post-dispatch verification and reconciliation
- Native Splunk scheduler and email workflow support
- Optional MergeReport workflow support
- Optional acknowledgement email support
- PyInstaller packaging support for desktop deployment

## Delivery Model Support

Splunk Utility Tool supports two common verification models:

1. **Native Splunk scheduler and email workflows**
   - verify dispatch and delivery using Splunk-accessible evidence
   - suitable when you rely on standard Splunk email or scheduler activity

2. **Optional MergeReport-based workflows**
   - use MergeReport evidence when your environment provides it
   - may improve post-dispatch visibility
   - not required for the tool to function

## High-Level Architecture

At a high level, the tool consists of:

- **UI layer**: Tkinter desktop workflow
- **Engine layer**: dispatch orchestration, slicing, timeout handling, reconciliation
- **Broker layer**: local request isolation and controlled Splunk API access
- **Verification layer**: native Splunk evidence plus optional MergeReport evidence
- **Packaging layer**: PyInstaller-based desktop builds

## Desktop UI Note

The desktop UI includes a lightweight built-in animated loader implemented in code. No external animation asset is required for the application to run.

## Setup

### Requirements

- Windows
- Python 3.11+ or a compatible packaged executable
- Access to the Splunk management API
- A Splunk account or service account with permission to dispatch the saved searches you intend to run

### Install dependencies

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Configuration overview

The project uses local config files for runtime settings.

Important:
- do **not** commit a real `config.ini`
- use `config.ini.example` or `config.example.ini` as your starting point
- keep `secret.dpapi` local only

Example values should look like:

- `https://your-splunk-host:8089`
- `your_service_account`
- `noreply@example.com`

## Running the Tool

From source:

```powershell
python main.py
```

For packaged builds, use the packaged executable and keep the config file beside it.

## Project Structure

```text
splunk-utility-tool/
├─ main.py
├─ splunk_engine.py
├─ splunk_report_tk.py
├─ postdispatch_monitor.py
├─ mergereport_monitor.py
├─ log_tailer.py
├─ progress_dialog.py
├─ ui_prompt.py
├─ ui_theme.py
├─ Internal/
├─ assets/
├─ config.ini.example
├─ config.example.ini
├─ requirements.txt
├─ README.md
├─ SECURITY.md
└─ LICENSE
```

## Security Notes

- Keep `config.ini` local and out of git
- Keep `secret.dpapi` local and out of git
- Prefer TLS verification in production
- Review sender and SMTP settings carefully before enabling acknowledgement email
- Public releases should not include runtime logs, local state, or environment-specific artifacts

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).

## Author

**Gabriel (Skyredt)**  
GitHub: https://github.com/Skyredt
