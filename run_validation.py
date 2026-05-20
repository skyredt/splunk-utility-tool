from __future__ import annotations
import os
import logging
from datetime import datetime

from splunk_engine import (
    load_config,
    SplunkClient,
    run_dispatch_multi,
    build_manual_reporting_window,
    build_slices,
    DispatchBatchController,
)
from Internal.security_policy import load_security_policy
from Internal.dpapi_store import load_or_enroll_password

def main():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    exe_dir = os.path.dirname(os.path.abspath(__file__))
    policy = load_security_policy(exe_dir=exe_dir)
    cfg = load_config(exe_dir=exe_dir, policy=policy)
    
    # Set the cooldown
    if cfg.dispatch_config is None:
        cfg.dispatch_config = {}
    cfg.dispatch_config['slice_cooldown_seconds'] = 60
    
    password, _ = load_or_enroll_password(
        prompt_fn=lambda: None,
        exe_dir=exe_dir,
        logger=logger,
        secret_file=cfg.secret_file,
    )
    
    client = SplunkClient(
        base_url=cfg.servers[0],
        username=cfg.username,
        password=password,
        verify_ssl=cfg.verify_ssl,
    )
    
    app = "search" # from context
    
    ids, names, email_flags = client.list_saved_searches(app)
    
    # The prompt mentions "[Splunk10] TestReport", so I will run only this one.
    try:
        report_index = names.index("[Splunk10] TestReport")
    except ValueError:
        print("Could not find report '[Splunk10] TestReport'")
        print("Available reports:")
        for name in names:
            print(f"- {name}")
        return

    selected_indices = [report_index]
    
    start = datetime(2026, 3, 12)
    end = datetime(2026, 3, 15)
    frequency = "Daily"
    
    starts, _ = build_slices(start, end, frequency)
    
    report_windows = {}
    for i in selected_indices:
        report_name = names[i]
        report_windows[report_name] = build_manual_reporting_window(report_name, start, end)
        
    
    for i in range(1): # run only once
        print(f"Running validation run {i+1} of 1")
        
        batch_controller = DispatchBatchController()

        params = {
            "client": client,
            "report_ids": [ids[report_index]],
            "report_names": [names[report_index]],
            "report_namespace_meta": [client._last_saved_search_namespace_meta[report_index]],
            "selected_indices": selected_indices,
            "frequency": frequency,
            "start": start,
            "end": end,
            "no_change": False,
            "wait_seconds": 30,
            "poll_interval": 5,
            "app": app,
            "resolved_windows": report_windows,
            "batch_controller": batch_controller,
            "config": cfg,
        }
        
        run_dispatch_multi(log_callback=print, sid_callback=lambda sid, name: print(f"Dispatched {name} with SID {sid}"), **params)
        
        print(f"Finished validation run {i+1} of 1")

if __name__ == "__main__":
    main()
