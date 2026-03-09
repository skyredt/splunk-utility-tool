## Pending Slice Behavior

Splunk Utility Tool v4 now uses a bounded active wait per slice.

- The tool waits up to `per_slice_wait_seconds` for active confirmation after a SID is issued.
- If Splunk explicitly reports a failed state, the slice is marked `FAILED`.
- If the wait budget expires first, the slice is marked `PENDING`.
- `PENDING` means the dispatch was accepted and may still complete asynchronously in Splunk.
- The batch continues to the next slice instead of stalling on one slow slice.
- A lightweight reconciliation pass can promote `PENDING` slices to `OK` or `FAILED` after all slices are attempted.
- Pilot default is `ack_enabled = 0`, so acknowledgement email is disabled unless operators opt in later.
- If ACK is enabled later, it is still skipped while pending slices remain unless `ack_on_pending = 1`.

Operator guidance:

- Treat `PENDING` as "not yet confirmed", not as failure.
- Review the final summary for separate `Succeeded`, `Failed`, and `Pending` counts.
- If slices remain pending, Splunk may still complete them later and send the reports asynchronously.
