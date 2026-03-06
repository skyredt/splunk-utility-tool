from __future__ import annotations

from auth_manager import build_auth_header, get_splunk_token, load_config
from splunk_engine import SplunkClient


def main() -> None:
    try:
        cfg = load_config()
        token = get_splunk_token()
        auth_header = build_auth_header(token)["Authorization"]
        client = SplunkClient(
            base_url=cfg.host,
            auth_mode="token",
            auth_header=auth_header,
        )
        client.validate_auth()
        print("SUCCESS")
    except Exception:
        print("FAILURE")


if __name__ == "__main__":
    main()
