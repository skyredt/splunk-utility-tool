CIO Splunk Utility Tool 4.0

Files:
- main.py           : launcher + token setup CLI helper
- splunk_engine.py  : core engine (REST, auth, dispatch logic)
- splunk_report_tk.py : Tk desktop UI
- config.ini        : Splunk connection and app settings

Authentication Modes
- `auth_mode=token` (recommended): uses `Authorization: Bearer <token>`.
- `auth_mode=password` (rollback): uses username/password login at `/services/auth/login`, then `Authorization: Splunk <sessionKey>`.
- `pass4SymmKey` is not used by this tool. It is for Splunk internal component trust (for example SHC/deployer), not client app authentication.

Token Storage
- Recommended: `token_storage=splunk_secret`
  - Store a Splunk-encrypted token (`$7$...`) in `token_encrypted`.
  - Runtime decryption uses local Splunk UF CLI and local `splunk.secret`.
- Development fallback: `token_storage=plain`
  - Reads clear token from `[splunk].token`.

How To Configure Encrypted Token
1. Configure:
   - `auth_mode = token`
   - `token_storage = splunk_secret`
2. Generate encrypted value:
   - `splunk.exe show-encrypted --value "<token>"`
3. Put output into `[splunk].token_encrypted`.
4. Validate:
   - `python tool.py --test-auth`

Self-Test Snippet (no secrets printed)
```
python tool.py --test-auth
```
