# Splunk Utility Tool 4.0 – Technical Implementation Notes

## 1. Project summary

Splunk Utility Tool 4.0 is a Python/Tkinter desktop operations utility for controlled Splunk saved-report regeneration. It is designed around practical Splunk administration workflows involving saved-search discovery, report selection, time slicing, dispatch, verification, reconciliation, batch tracking, and optional acknowledgment summaries.

Project status: Functional operational utility.

The tool runs as a desktop client outside Splunk. It does not replace Splunk's scheduler, does not run inside Splunk Web, and acts as a client-side orchestration layer over Splunk saved-search dispatch workflows. The public repository is sanitized and does not include real production configuration or runtime artifacts.

## Who this page is for

This page is intended for technical readers who want to understand the design decisions behind the public-safe Splunk Utility Tool project. It focuses on workflow control, dispatch safety, request handling, and documentation boundaries rather than production environment details.

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

For larger recovery work, the expected benefit is reduced manual coordination and more repeatable dispatch review, not a formally benchmarked performance claim. A submitted Splunk job did not always mean the report was successfully sent.

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

Confirmed implementation themes in the repository include a Tkinter desktop UI, Splunk saved-search dispatch, date/time slicing, slice-by-slice tracking, bounded retry and reconciliation, post-dispatch verification using Splunk-accessible evidence, optional MergeReport-based verification where available, optional acknowledgment email summaries, batch ID tracking, request-level isolation for safer Splunk REST execution, Windows desktop packaging support with PyInstaller, configuration examples using fake Splunk values, and a security-conscious public repo that avoids real config, secrets, logs, hostnames, or production artifacts.

## 4. Operational workflow

The core execution idea is:

```text
Dispatch -> wait -> verify -> reconcile -> finalize
```

This core lifecycle applies to an individual report or dispatch slice. The Bus vs Plane model determines whether those units are processed one-by-one or batched.

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

The Check and Dispatch workflow follows the core dispatch, verification, reconciliation, and finalization sequence described above. The tool does not assume that a submitted Splunk dispatch means the report was successfully delivered.

If a report has uncertain status, the tool can move it into reconciliation instead of immediately marking it failed. If the issue cannot be safely resolved, the operator can escalate using the batch ID and summary context.

## 6. Time slicing

The tool supports daily, weekly, monthly, and custom datetime slicing. For larger regeneration windows, it breaks the request into slices, dispatches each slice separately, tracks each slice as an execution unit, and rolls the outcome into the final batch summary.

Each slice is treated as a trackable execution unit with its own dispatch status, SID where available, verification result, reconciliation state, and final outcome. This avoids assuming that one large date range or one submitted job is automatically equivalent to successful report delivery.

In the current engine, the run plan is built before dispatch. Non-custom date modes create per-report slice executions, while custom datetime mode creates a single custom execution per selected report. The implementation also guards against date ranges that generate no slices or too many slices.

## 7. Bus vs Plane execution model

The Bus vs Plane model controls the order of dispatch and verification based on the number of execution units after slicing.

Plane style applies to 7 or fewer execution units. It follows a "check first, then dispatch" pattern: each unit is dispatched and checked before the next unit is dispatched.

Bus style applies to 8 or more execution units. It follows a "dispatch first, then check" pattern: all execution units are dispatched first, then verification and reconciliation run across the batch afterward.

The threshold is based on post-slicing execution count, not raw selected report count. For example, one report sliced into 30 daily windows produces 30 execution units and uses Bus style.

## 8. Request-level isolation

The dispatch path is documented in terms of request-level isolation: each dispatch request should avoid contaminating subsequent request handling when a timeout or transport failure occurs. This is narrower than claiming full process-wide or authentication-session isolation.

Implementation notes: where the public code exposes request-transport behavior, the relevant concern is HTTP session isolation and bounded handling of dispatch-critical REST calls. The documentation does not claim a new authentication login for every slice.

## 9. Handling uncertainty and reconciliation

One of the main engineering challenges is Splunk's asynchronous job behavior. A dispatch request can be accepted before the report is actually sent. A timeout does not always mean the report failed. A missing or delayed SID can also create uncertainty during report regeneration.

Splunk Utility Tool 4.0 handles this by separating dispatch submission from final success. It treats each report slice as a trackable execution unit and moves uncertain results into bounded reconciliation instead of immediately marking them as failed.

The engine tracks pending dispatch attempts, can attach a late SID if a timed-out request eventually returns one, and performs bounded reconciliation sweeps for unresolved slices. Final states distinguish success, failure, pending verification, expired pending work, and partial outcomes.

## 10. Multi-app selection

The tool supports multi-app batch selection. An operator can select reports from one Splunk app, move to another app, select additional reports, and review the full combined batch before dispatch.

Persistent selection is preserved across app/search filtering, so hidden selected reports remain selected until the operator explicitly clears or changes them.

## 11. Batch tracking and accountability

Each regeneration run is assigned a batch ID for traceability. The tool records batch context such as selected reports, slices, timestamps, triggering user, and final outcome. This makes follow-up more precise because users and operators can reference a specific regeneration run instead of vaguely describing "the Monday report" or "the failed resend."

The repository also includes local journal and recovery behavior for unfinished batches. Operators can inspect, reconcile/finalize, or dismiss archived unfinished work instead of blindly rerunning overlapping work.

## 12. Technical architecture

| Layer | Responsibility |
|---|---|
| UI layer | Tkinter desktop interface for app/report selection, time range selection, progress, and logs |
| Engine layer | Dispatch orchestration, slicing, state tracking, timeout handling, and reconciliation |
| Request transport/API layer | Request-level isolation and controlled Splunk Management API access |
| Verification layer | Post-dispatch checking using native Splunk evidence and optional MergeReport evidence |
| Packaging layer | Windows desktop packaging support using PyInstaller |

## 13. Splunk concepts demonstrated

The tool interacts with Splunk saved-search dispatch workflows, including saved-search execution, SID tracking, app scoping, and post-dispatch status review through Splunk-accessible evidence.

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

## 15. Expected operational impact

The expected benefit is reduced manual coordination and more repeatable dispatch review, not a formally benchmarked performance claim. The tool is intended to make repeated report regeneration easier to plan, review, and follow up through explicit selection state, batch context, and post-dispatch review.

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
| Python desktop automation | Tkinter workflow for saved-report regeneration |
| Controlled Splunk API workflow | Saved-search selection, dispatch, status review, and batch context |
| Selection-state handling | Multi-app selection and confirmation before dispatch |
| Asynchronous dispatch safety | Timeout handling, bounded reconciliation, and request-level isolation |
| Public-safe documentation discipline | Sanitized examples, explicit non-goals, and no exposed environment details |

## 18. Validation status

This implementation update includes source, test, and documentation changes for the Bus vs Plane execution model.

For this documentation update, validation consisted of:

- `python -m py_compile main.py splunk_report_tk.py splunk_engine.py`
- Focused unit tests for Bus vs Plane execution behavior
- `git diff --check`
- Sensitive-value scan of changed documentation files
- Targeted overclaim scan of changed documentation files

The broader test-stabilization branch is intentionally tracked separately because it was based on a different source/test baseline from the current public `main` branch.

## 19. Boundaries and non-goals

- The tool does not replace Splunk's scheduler.
- The tool does not guarantee report delivery.
- The tool does not run inside Splunk Web.
- The public repo is not a dump of internal production tooling.
- The public repo should not include real credentials, hostnames, report names, recipients, production logs, or internal screenshots.
- The tool improves regeneration control, verification, and accountability, but final confirmation still depends on available Splunk/tool evidence.
