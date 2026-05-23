# Splunk Utility Tool 4.0 – Technical Implementation Notes

## 1. Project summary

Splunk Utility Tool 4.0 is a Python/Tkinter desktop operations utility for controlled Splunk saved-report regeneration. It is designed around practical Splunk administration workflows involving saved-search discovery, report selection, time slicing, dispatch, verification, reconciliation, batch tracking, and optional acknowledgment summaries.

Project status: working tool used/tested in realistic Splunk operations workflow.

The tool runs as a desktop client outside Splunk. It does not replace Splunk's scheduler, does not run inside Splunk Web, and acts as a client-side orchestration layer over Splunk saved-search dispatch workflows. The public repository is sanitized and does not include real production configuration or runtime artifacts.

## 2. Problem statement

When users do not receive scheduled Splunk reports, the Splunk team should not need to manually locate, rerun, check, and resend every report through Splunk Web.

Before the tool, the manual process was:

1. Open Splunk Web.
2. Locate the correct saved search.
3. Confirm or adjust the report time range.
4. Run the report.
5. Wait for completion.
6. Check whether report output or email delivery succeeded.
7. Repeat for every report or every time slice.

The operational pain points are repeated regeneration requests, manual report handling, slow bulk resend work after an incident, weak evidence that a submitted Splunk job was actually sent, and weak accountability when tracing who triggered a resend, when, and for which batch.

Bulk resend after an incident could take 1 to 2 days manually. A submitted Splunk job did not always mean the report was successfully sent.

## 3. Design goals

The tool provides a controlled regeneration workflow for Splunk saved reports. Operators can:

- Scope reports by Splunk app.
- Search available reports.
- Select reports across one or more apps.
- Choose a regeneration date range.
- Use daily, weekly, monthly, or custom slicing.
- Review the final combined batch before dispatch.
- Dispatch reports or report slices.
- Check dispatch and post-dispatch evidence.
- Reconcile uncertain results where possible.
- Produce an acknowledgment summary with batch context.

Confirmed implementation themes in the repository include a Tkinter desktop UI, Splunk saved-search dispatch, date/time slicing, slice-by-slice tracking, bounded retry and reconciliation, post-dispatch verification using Splunk-accessible evidence, optional MergeReport-based verification where available, optional acknowledgment email summaries, batch ID tracking, local broker/session/request isolation for safer Splunk REST execution, Windows desktop packaging support with PyInstaller, configuration examples using fake Splunk values, and a security-conscious public repo that avoids real config, secrets, logs, hostnames, or production artifacts.

## 4. Operational workflow

The core execution idea is:

```text
Dispatch -> wait -> verify -> reconcile -> finalize
```

At a high level, the workflow is:

1. Connect to a configured Splunk Management API endpoint.
2. Load available Splunk apps.
3. Load saved searches for the selected app.
4. Let the operator search and select reports.
5. Build a run plan from selected reports and the requested time mode.
6. Show the planned report/slice count before dispatch.
7. Dispatch each report or slice according to the execution model.
8. Track SIDs where Splunk returns them.
9. Verify completed work using Splunk/tool evidence.
10. Reconcile uncertain or pending outcomes where possible.
11. Finalize the batch with a summary and optional acknowledgment email.

## 5. Check and Dispatch workflow

The strongest workflow in the tool is Check and Dispatch. The tool does not assume that a submitted Splunk dispatch means the report was successfully delivered. It dispatches selected reports or slices, checks available Splunk/tool evidence, reconciles uncertain results where possible, and then produces a final result summary.

If a report has uncertain status, the tool can move it into reconciliation instead of immediately marking it failed. If the issue cannot be safely resolved, the operator can escalate using the batch ID and summary context.

## 6. Time slicing

The tool supports daily, weekly, monthly, and custom datetime slicing. For larger regeneration windows, it breaks the request into slices, dispatches each slice separately, tracks each slice as an execution unit, and rolls the outcome into the final batch summary.

Each slice is treated as a trackable execution unit with its own dispatch status, SID where available, verification result, reconciliation state, and final outcome. This avoids assuming that one large date range or one submitted job is automatically equivalent to successful report delivery.

In the current engine, the run plan is built before dispatch. Non-custom date modes create per-report slice executions, while custom datetime mode creates a single custom execution per selected report. The implementation also guards against date ranges that generate no slices or too many slices.

## 7. Bus vs Plane execution model

The tool uses two execution patterns depending on batch size.

| Batch size | Model | Behavior |
|---:|---|---|
| 1 to 7 reports | Plane model | Dispatch one report or slice, check status, then continue |
| 8 or more reports | Bus model | Dispatch selected reports/slices first, then verify each report or slice afterward |

The Plane model is used for smaller resend requests where safety and immediate checking matter more. The Bus model is used for larger batches where waiting after each report would waste operator time. This keeps small batches deliberate and safe, while larger recovery batches avoid unnecessary operator waiting time.

In code, this is represented by a selected-report-count handling threshold. Larger batches enter the throughput path and log that planned executions are dispatched first, with verification following afterward.

## 8. Broker/session/request isolation

The tool implements local broker/session isolation for dispatch-critical Splunk REST calls. Dispatch and verification paths can use isolated client/request transport instead of relying on one shared long-lived HTTP connection, helping prevent one timeout, stale connection, or interrupted request from contaminating later dispatch work.

The implementation supports isolated Splunk client/request transport, not necessarily a new authentication login for every slice. Relevant code paths include isolated client cloning, isolated dispatch/rest client creation, fresh `requests.Session()` creation, one-shot request transport, and dispatch metadata such as `transport_mode = "oneshot_request"` and `transport_freshness = "fresh_oneshot_session"`.

## 9. Handling uncertainty and reconciliation

One of the main engineering challenges is Splunk's asynchronous job behavior. A dispatch request can be accepted before the report is actually sent. A timeout does not always mean the report failed. A missing or delayed SID can also create uncertainty during report regeneration.

Splunk Utility Tool 4.0 handles this by separating dispatch submission from final success. It treats each report slice as a trackable execution unit and moves uncertain results into bounded reconciliation instead of immediately marking them as failed.

The engine tracks pending dispatch attempts, can attach a late SID if a timed-out request eventually returns one, and performs bounded reconciliation sweeps for unresolved slices. Final states distinguish success, failure, pending verification, expired pending work, and partial outcomes.

## 10. Multi-app selection

The tool supports multi-app batch selection. An operator can select reports from one Splunk app, move to another app, select additional reports, and review the full combined batch before dispatch.

Persistent selection is preserved across app/search filtering, so hidden selected reports remain selected until the operator explicitly clears or changes them.

## 11. Batch tracking and accountability

Each regeneration run is assigned a batch ID for traceability. The tool records batch context such as selected reports, slices, timestamps, triggering user, and final outcome. This makes follow-up more precise because users and operators can reference a specific regeneration run instead of vaguely describing "the Monday report" or "the failed resend."

Batch IDs turn report resends into traceable operational events.

The repository also includes local journal and recovery behavior for unfinished batches. Operators can inspect, reconcile/finalize, or dismiss archived unfinished work instead of blindly rerunning overlapping work.

## 12. Technical architecture

| Layer | Responsibility |
|---|---|
| UI layer | Tkinter desktop interface for app/report selection, time range selection, progress, and logs |
| Engine layer | Dispatch orchestration, slicing, state tracking, timeout handling, and reconciliation |
| Broker/API layer | Local broker/session/request isolation and controlled Splunk Management API access |
| Verification layer | Post-dispatch checking using native Splunk evidence and optional MergeReport evidence |
| Packaging layer | Windows desktop packaging support using PyInstaller |

## 13. Splunk concepts demonstrated

The project demonstrates implementation-level handling of these Splunk concepts:

- Saved searches.
- Scheduled reports.
- Splunk Management API.
- `/servicesNS/-/{app}/saved/searches`.
- Saved-search dispatch.
- Search jobs.
- SID tracking.
- Scheduler/email workflow awareness.
- Native Splunk evidence.
- Optional MergeReport verification.
- App scoping.
- Report ownership/app namespace handling.
- Splunk REST timeout behavior.
- Post-dispatch monitoring.

## 14. Tech stack

| Area | Technology |
|---|---|
| Language | Python |
| UI | Tkinter |
| Platform | Windows desktop |
| Splunk integration | Splunk Management API |
| HTTP/API layer | Requests / Splunk REST calls |
| Splunk concepts | Saved searches, dispatch, search jobs, SID, scheduler/email workflow |
| Verification | Native Splunk evidence, optional MergeReport evidence |
| Packaging | PyInstaller |
| Configuration | Local config files with fake public examples |
| Security posture | Sanitized public repo, no real credentials, no internal hostnames, no production logs |

## 15. Estimated operational impact

These are operational estimates based on the manual steps involved, not formal benchmark results.

| Scenario | Manual process | With tool |
|---|---:|---:|
| Normal resend request, 4 to 10 reports | Around 30 minutes | Around 5 minutes |
| Large recovery involving hundreds of scheduled reports | 1 to 2 days | Under 30 minutes operator handling time |

## 16. Public-safe documentation and security controls

Safe to show:

- GitHub repository.
- Architecture diagram.
- Sanitized Tkinter UI screenshots.
- Report selection / confirmation screenshot.
- Fake Splunk configuration example.
- Short demo using dummy reports.
- Sanitized acknowledgment summary, optional.
- Sanitized execution log, optional only if fully sanitized.

Do not show:

- Internal Splunk hostnames.
- Real Splunk URLs.
- Real saved search/report names if sensitive.
- Real app names if sensitive.
- Real usernames.
- Real email recipients.
- Real batch IDs from internal runs.
- Real execution logs from production.
- Credentials, tokens, DPAPI secrets, or `config.ini`.
- Internal operational screenshots with environment details.

Repository security rules:

- Do not commit real `config.ini`.
- Use `config.ini.example` or `config.example.ini`.
- Keep `secret.dpapi` local only.
- Public releases should not include runtime logs, local state, or environment-specific artifacts.
- Example Splunk URL should look like `https://your-splunk-host:8089`.

## 17. What this project demonstrates

| Capability | Demonstrated through |
|---|---|
| Splunk administration | Saved-search discovery, dispatch, scheduler/email workflow awareness |
| SIEM operations | Report regeneration, recovery handling, controlled operator workflow |
| Python automation | Desktop orchestration tool with dispatch, slicing, verification, and state tracking |
| Reliability engineering | Timeout handling, bounded reconciliation, retry behavior, and batch status tracking |
| Security-conscious design | Sanitized config, no exposed internal details, public-safe proof |
| Operator UX | Multi-app selection, confirmation workflow, progress tracking, acknowledgment summary |
| API integration | Controlled Splunk Management API calls and request isolation |

## 18. Validation status

This documentation page is part of a public-safe documentation update for the Splunk Utility Tool repository.

For this documentation-only branch, validation consisted of:

```bash
git diff --check
```

No source-code or unit-test stabilization changes are included in this branch.

## 19. Boundaries and non-goals

- The tool does not replace Splunk's scheduler.
- The tool does not guarantee report delivery.
- The tool does not run inside Splunk Web.
- The public repo is not a dump of internal production tooling.
- The public repo should not include real credentials, hostnames, report names, recipients, production logs, or internal screenshots.
- The tool improves regeneration control, verification, and accountability, but final confirmation still depends on available Splunk/tool evidence.
