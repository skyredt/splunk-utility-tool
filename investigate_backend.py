
import os
import sys

# Add the root directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from Internal.splunk_broker import SplunkBrokerProxyClient
from splunk_engine import load_config
from Internal.security_policy import SecurityPolicy

def main():
    """
    Investigates the Splunk backend for a specific SID to diagnose why an alert action might have failed.
    """
    # ==================================================================================================
    # IMPORTANT: Please replace the placeholder SID with the actual SID for the 3rd slice.
    # The 3rd slice covers the time range 2026-03-14 to 2026-03-15 and was dispatched around 02:57 AM.
    # ==================================================================================================
    sid = "skyred5_search_RMD5ea7a51464c99c9d5_at_1773514634_90"

    if sid == "placeholder_sid":
        print("Please replace the 'placeholder_sid' in this script with the actual SID and run again.")
        return

    print(f"Investigating SID: {sid}")

    try:
        exe_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Create a basic security policy
        policy = SecurityPolicy.from_json_string('{"build_mode": "dev", "policy_mode": "permissive", "allow_insecure_overrides": true}')

        config = load_config(exe_dir=exe_dir, policy=policy)
        
        # Assuming the first server in the config is the target
        server_url = config.servers[0]
        
        # The SplunkBrokerProxyClient will handle authentication
        client = SplunkBrokerProxyClient(
            splunkd_uri=server_url,
            exe_dir=exe_dir,
            policy=policy,
            config=config,
            # These are not needed for a simple query
            log_broker_url="",
            log_broker_token="",

        )

        spl_query = f'''
            search index=_internal (sourcetype=splunkd OR sourcetype=scheduler) sid="{sid}"
            | search component=AlertManager OR component=SavedSplunker OR component=SendEmail OR component=mergeReport
            | table _time, log_level, component, message
        '''

        print(f"Executing SPL query against {server_url}...")
        
        # Using oneshot search
        results = client.oneshot(spl_query, count=0)

        print("""
--- Backend Log Analysis ---""")
        if results:
            for result in results:
                print(f"Time: {result.get('_time')}, Level: {result.get('log_level')}, Component: {result.get('component')}, Message: {result.get('message')}")
        else:
            print("No results found for the given SID and query. The backend did not log any relevant events.")
        print("""--------------------------
""")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
