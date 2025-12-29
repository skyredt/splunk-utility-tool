from __future__ import annotations

import configparser
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional, Tuple
from urllib.parse import urlparse

try:
    from PySide6.QtCore import QObject, Signal  # type: ignore
except Exception:  # PySide6 may not be installed for Tk-only usage
    class QObject:  # minimal fallback
        pass

    class Signal:  # minimal fallback that provides an emit() method
        def __init__(self, *args, **kwargs):
            pass

        def emit(self, *args, **kwargs):
            return None
import requests


@dataclass
class SplunkConfig:
    servers: List[str]
    username: str
    password: str


def load_config(path: str = "config.ini") -> SplunkConfig:
    cfg = configparser.ConfigParser()
    read_files = cfg.read(path)
    if not read_files:
        raise FileNotFoundError(f"Config file not found: {path}")

    if "splunk" not in cfg:
        raise KeyError("Missing [splunk] section in config.ini")

    servers_raw = cfg["splunk"].get("servers", "")
    servers = [s.strip() for s in servers_raw.split(";") if s.strip()]
    if not servers:
        raise ValueError("No servers defined in [splunk].servers")

    username = cfg["splunk"].get("username", "")
    password = cfg["splunk"].get("password", "")
    if not username or not password:
        raise ValueError("username/password not set in [splunk]")

    return SplunkConfig(servers=servers, username=username, password=password)


class SplunkClient(QObject):
    finished = Signal()
    error = Signal(str)
    apps_loaded = Signal(list)
    searches_loaded = Signal(list, list)
    dispatch_log = Signal(list)

    def __init__(self, base_url: str, username: str, password: str):
        super().__init__()
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (username, password)
        # For now, do not verify SSL (lab use). You can change this later.
        self.session.verify = False
        self.session.headers.update(
            {
                "Content-Type": "application/x-www-form-urlencoded",
            }
        )

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        url = self.base_url + path
        merged = {"output_mode": "json", "count": 0}
        if params:
            merged.update(params)
        resp = self.session.get(url, params=merged, timeout=60)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, data: Optional[dict] = None) -> dict:
        url = self.base_url + path
        merged = {"output_mode": "json"}
        if data:
            merged.update(data)
        resp = self.session.post(url, data=merged, timeout=60)
        resp.raise_for_status()
        try:
            return resp.json()
        except json.JSONDecodeError:
            return {"_raw": resp.text}

    def list_apps(self):
        try:
            data = self._get("/services/apps/local")
            apps: List[str] = []
            for entry in data.get("entry", []):
                content = entry.get("content", {})
                if not content.get("visible", False):
                    continue
                name = entry.get("name")
                # Filter similar to original tool
                if name in {
                    "launcher",
                    "splunk_instrumentation",
                    "user-prefs",
                    "gettingstarted",
                }:
                    continue
                apps.append(name)
            apps_sorted = sorted(apps)
            self.apps_loaded.emit(apps_sorted)
            return apps_sorted
        except Exception as e:
            self.error.emit(f"Failed to list apps: {e!r}")
        finally:
            self.finished.emit()

    def list_saved_searches(self, app: str):
        try:
            data = self._get(f"/servicesNS/-/{app}/saved/searches")
            ids: List[str] = []
            names: List[str] = []
            email_flags: List[bool] = []
            for entry in data.get("entry", []):
                acl = entry.get("acl", {})
                if acl.get("app") != app:
                    continue
                ids.append(entry.get("id", ""))
                names.append(entry.get("name", ""))
                # Detect if the saved search has an email action enabled.
                content = entry.get("content", {})
                flag = False
                # Common Splunk saved search structures may include 'action.email'
                # or an 'actions' collection indicating enabled actions.
                ae = content.get("action.email")
                if ae in (1, "1", True, "true", "True"):
                    flag = True
                else:
                    acts = content.get("actions")
                    if isinstance(acts, dict) and acts.get("email"):
                        flag = True
                    elif isinstance(acts, list) and "email" in acts:
                        flag = True
                email_flags.append(flag)
            # Keep existing signal for compatibility (two-arg signature).
            self.searches_loaded.emit(ids, names)
            return ids, names, email_flags
        except Exception as e:
            self.error.emit(f"Failed to list saved searches for app '{app}': {e!r}")
        finally:
            self.finished.emit()

    def dispatch_saved_search(
        self,
        report_id_url: str,
        earliest: Optional[str] = None,
        latest: Optional[str] = None,
        trigger_actions: bool = True,
    ) -> Tuple[bool, Optional[str], str]:
        """
        Dispatch a saved search.

        Returns (ok, sid, error_message).
        """
        path = urlparse(report_id_url).path  # /servicesNS/.../saved/searches/<name>
        data: dict = {}
        if trigger_actions:
            data["trigger_actions"] = 1
        if earliest is not None:
            data["dispatch.earliest_time"] = earliest
        if latest is not None:
            data["dispatch.latest_time"] = latest

        try:
            resp = self.session.post(
                self.base_url + path + "/dispatch",
                data={"output_mode": "json", **data},
                timeout=60,
            )
        except Exception as e:
            return False, None, f"Request error: {e!r}"

        if resp.status_code not in (200, 201):
            return False, None, f"HTTP {resp.status_code}: {resp.text[:500]}"

        try:
            payload = resp.json()
        except json.JSONDecodeError:
            return False, None, f"Non-JSON response: {resp.text[:500]}"

        sid = payload.get("sid")
        if not sid:
            return False, None, f"No sid in dispatch response: {payload}"

        return True, sid, ""

    def check_job_status(
        self, sid: str, wait_seconds: int = 10, poll_interval: int = 2
    ) -> Tuple[str, dict]:
        """
        Check job status for a given sid.

        Returns (state, content) where state is 'SUCCESS', 'FAILED', or 'TIMEOUT'.
        """
        import time

        last_content: dict = {}
        deadline = time.time() + wait_seconds

        while time.time() < deadline:
            data = self._get(f"/services/search/jobs/{sid}")
            entry = data.get("entry", [{}])[0]
            content = entry.get("content", {})
            last_content = content

            is_done = content.get("isDone")
            dispatch_state = content.get("dispatchState")

            if is_done:
                if dispatch_state in ("DONE", "SUCCESS", None):
                    return "SUCCESS", content
                else:
                    return "FAILED", content

            time.sleep(poll_interval)

        return "TIMEOUT", last_content


def build_slices(start: datetime, end: datetime, frequency: str):
    starts: List[datetime] = []
    ends: List[datetime] = []

    pointer = start

    if end <= start:
        return starts, ends

    while pointer < end:
        starts.append(pointer)

        if frequency == "Monthly":
            year = pointer.year + (pointer.month // 12)
            month = pointer.month % 12 + 1
            next_pointer = datetime(year, month, 1)
            if (end - pointer).days < 7:
                next_pointer = end

        elif frequency == "Weekly":
            if (end - pointer).days >= 7:
                next_pointer = pointer + timedelta(days=7)
            else:
                next_pointer = end

        elif frequency == "Daily":
            next_pointer = pointer + timedelta(days=1)

        else:
            raise ValueError(f"Unknown frequency: {frequency}")

        if next_pointer > end:
            next_pointer = end

        ends.append(next_pointer)
        pointer = next_pointer

    return starts, ends


def to_epoch(dt: datetime) -> str:
    return str(int(dt.timestamp()))


def run_dispatch_single(
    client: SplunkClient,
    report_id_url: str,
    report_name: str,
    frequency: str,
    start: datetime,
    end: datetime,
    no_change: bool,
) -> List[str]:
    logs: List[str] = []

    if no_change:
        logs.append(
            f"Dispatching '{report_name}' with saved search time range..."
        )
        ok, sid, err = client.dispatch_saved_search(report_id_url)
        if not ok:
            logs.append(f"  FAILED: {err}")
        elif sid is not None:
            state, info = client.check_job_status(sid)
            if state == "SUCCESS":
                logs.append(f"  OK (sid={sid})")
            elif state == "FAILED":
                logs.append(
                    f"  FAILED (sid={sid}, state={info.get('dispatchState')})"
                )
            else:
                logs.append(
                    f"  UNKNOWN (sid={sid}) – job still running / timeout while checking"
                )
        return logs

    starts, ends = build_slices(start, end, frequency)

    if len(starts) == 0:
        raise ValueError("Selected date range generates 0 slices/emails.")
    if len(starts) > 12:
        raise ValueError("Selected date range generates more than 12 slices/emails.")

    logs.append(
        f"Dispatching '{report_name}' with {len(starts)} slice(s) ({frequency}) from {start} to {end}."
    )

    for i, (s, e) in enumerate(zip(starts, ends), start=1):
        earliest = to_epoch(s)
        latest = to_epoch(e)
        logs.append(
            f"  [{i}/{len(starts)}] Earliest: {s}, Latest: {e} – sending..."
        )
        ok, sid, err = client.dispatch_saved_search(
            report_id_url, earliest=earliest, latest=latest
        )
        if not ok:
            logs.append(f"  [{i}/{len(starts)}] FAILED: {err}")
            continue

        if sid is None:
            logs.append(f"  [{i}/{len(starts)}] FAILED: No sid returned")
            continue

        state, info = client.check_job_status(sid)
        if state == "SUCCESS":
            logs.append(f"  [{i}/{len(starts)}] OK (sid={sid})")
        elif state == "FAILED":
            logs.append(
                f"  [{i}/{len(starts)}] FAILED (sid={sid}, state={info.get('dispatchState')})"
            )
        else:
            logs.append(
                f"  [{i}/{len(starts)}] UNKNOWN (sid={sid}) – job still running / timeout while checking"
            )

    return logs


def run_dispatch_multi(
    client: SplunkClient,
    report_ids: List[str],
    report_names: List[str],
    selected_indices: List[int],
    frequency: str,
    start: datetime,
    end: datetime,
    no_change: bool,
) -> List[str]:
    try:
        logs: List[str] = []
        if not selected_indices:
            raise ValueError("No reports selected.")

        logs.append(
            f"Starting dispatch for {len(selected_indices)} report(s) – frequency={frequency}, range={start} → {end}, no_change={no_change}"
        )

        ok_count = 0
        fail_count = 0
        unknown_count = 0

        for idx_num, i in enumerate(selected_indices, start=1):
            report_id_url = report_ids[i]
            report_name = report_names[i]

            logs.append("")
            logs.append(f"=== [{idx_num}/{len(selected_indices)}] {report_name} ===")

            report_logs = run_dispatch_single(
                client,
                report_id_url=report_id_url,
                report_name=report_name,
                frequency=frequency,
                start=start,
                end=end,
                no_change=no_change,
            )
            logs.extend(report_logs)

            if any("FAILED" in line for line in report_logs):
                fail_count += 1
            elif any("UNKNOWN" in line for line in report_logs):
                unknown_count += 1
            else:
                ok_count += 1

        logs.append("")
        logs.append(
            f"Summary: {ok_count} OK, {fail_count} failed, {unknown_count} unknown out of {len(selected_indices)} report(s)."
        )
        client.dispatch_log.emit(logs)
        return logs
    except Exception as e:
        client.error.emit(f"Error during dispatch: {e!r}")
        return []
    finally:
        client.finished.emit()
