Splunk Utility Tool v3.0 (Skeleton)

Files:
- main.py           : PySide6 GUI entrypoint (Reports tab only)
- splunk_engine.py  : Core engine (REST, dispatch logic, multi-report support)
- config.ini        : Basic Splunk connection settings

Quick start:
1. Create a virtual env (optional but recommended):
   python -m venv .venv
   .venv\Scripts\activate  (Windows)
   source .venv/bin/activate (Linux/macOS)

2. Install dependencies:
   pip install PySide6 requests

3. Edit config.ini with your Splunk servers and credentials.

4. Run:
   python main.py

This is a minimal working base for Splunk Utility Tool v3.0.
You can extend the UI (tabs, feedback, status) without touching splunk_engine.py.
