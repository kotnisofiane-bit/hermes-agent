---
title: "B2B C1 Producer Contract"
description: "P2 governed context admission and the closed B2B execution boundary"
---

# B2B C1 producer contract (P2)

This is dubsar-platform PR120 (§5 P2) and task L13-D4: the *Hermes* C1 path —
governed context produced by the installed `dubsar-agent-context` plugin.
It is distinct from the operational model-path criterion C1 in L13-D4. Scope reference:
https://github.com/kotnisofiane-bit/dubsar-platform/pull/120

The original native evidence below records `dde57dec` and its preceding P2
implementation. The pass-2 interface now requires a Python `prepare_context`
hook. The external producer at `dubsar-hermes-profile@05d7394c` does not yet
register it: admission with that unchanged plugin fails closed (`503
execution_unavailable`, no durable rows — the native `legacy_plugin` case
proves exactly this). This repository
proves the generic contract with an unrelated directory plugin; enabling the
native producer again requires the separate plugin change, not a core fallback.
The native positive path therefore runs against a task-local checkout of the
same pin with the external `prepare_context` patch applied for tests only
(`unpatched_profile` in `.p2-native-runtime.json` keeps an unmodified copy for
the negative case). Only a callback registered through
`PluginContext.register_hook` counts — configured outbound webhooks, shell
hooks and the dashboard hook form refuse `prepare_context` at configuration,
and the producer's own plugin must also register `pre_llm_call` under the same
owner, or admission fails closed before any durable write.

## Delivery boundary

The native integration lane proved the original P2 composition locally, not an
installed deployment. Admission requires a live, current, mission-scoped
context preparation supplied by exactly one `prepare_context` hook registered
under the owning profile. The concrete external producer is responsible for
real native My Work mission reads
(`createB2BMissionPorts`), a real native Operational Context kernel read
(`dubsar.my-work-oc-context-view/2` with a measured state projection), and a
mission-qualified Memory Plane v2 read. Preparation runs before `b2b_admit`,
title changes or worker launch; it performs no durable write, no admission,
no agent construction and no provider call. Actual publication still happens
only inside the admitted worker's real `pre_llm_call` hook.

Installed configuration, plugin presence, valid schema hashes and an inert
constructor remain preparation, not evidence of readiness. A lane without a
current mission-scoped proof reports `not-ready` with a typed code
(`execution_inputs_unavailable`, `c1_producer_unavailable`, or
`c1_context_required`) — health evaluation performs no plugin discovery or
probe and cannot leak ambient execution state. A missing, crossed, stale,
future-dated, late or otherwise unqualified source fails closed with
`503 execution_unavailable` before admission. That refusal covers NEW
admissions only: an already-durable attempt is always served by the
idempotent replay (`_replayed_response`) before the readiness guard, so a
lost-ACK retry recovers its run — and any error entering the profile scope
or reading the serving config still answers the same typed 503, never an
untyped 500. No attempt or binding is created by that refusal.

## Proof semantics

The preparation binds, immutably: the exact Hermes home (resolved path), the
frozen policy frame and catalogue project JSON, the profile's plugin manager
and registered callback identities, plus the plugin-owned configuration
validator, and the native OC `/2` source
observation —
`state_projection.candidate.result_kind == "measured"` with explicit
`source_observed_at` and a positive integer `freshness_max_age_ms`. The
source window `observed <= now < observed + min(900000, freshness_max_age_ms)`
is enforced at preparation, publication, configuration and every recheck;
its deadline is stored in the preparation and is never extended by provider
delay or another TTL.

The POST's signed envelopes are checked again immediately before durable
admission. Their short expiry does not govern preparation or publication after
admission. Source authority is renewed by `before_provider`; the OC observation
bound is never renewed. Typed preparation refusals reach the durable attempt
classification without being replaced by a fixed `context_unavailable` reason.
New attempts check capacity before native preparation and again afterwards,
without reserving a slot; durable replay keeps its existing bypass.

`/1` OC receipts and view/capture instants are never
source observation and refuse as `context_oc_unqualified`. Preparation also
validates the candidate render before admission (UTF-8, nonempty,
≤ `CONTEXT_MAX_BYTES`, ≤ 9000 chars, `bounds.render_chars` exact); the
publication receipt then preserves the fresh hook render — not necessarily
byte-identical to the preflight render, since fresh native view refs differ.
Publication relies
on the fresh hook receipt: `assert_current`, `assert_source_equivalent`,
receipt freshness and source-basis equality — no second unbounded native
read. Replay of the same run/attempt returns the durable result and never
dispatches again, even after the Memory Plane later becomes unavailable
(the signed Portal source must still resolve for the replay request).

## Ownership and inputs

Only trusted host/plugin code in the owning profile scope may produce C1.
The API launcher owns the `BoundExecution` capability: it is minted from the
verified Portal source exchange and immutable operator catalog, never from
a model response, an HTTP context upload or a caller-supplied prompt.

The producer consumes that exact capability and its frozen `project` policy:
native My Work `project_id`, absolute existing `project_context.start` and
`allocation_root`, `logical_mission`, allowed namespaces, and pinned r2
contract root. Native project ids are not Memory Plane ids (`alpha`/`beta`);
the logical Memory Plane project is resolved through `logical_mission`.
Mission id, revision, reservation and authority digests come from the
verified binding, not the profile's default mission selector.

The readonly plugin requires an explicit v2/v2.r2 configuration, approved
Memory Plane origin, and allowlisted My Work and OC read ports. Its bound
factory must create execution-local adapters without changing shared profile
mappings. The base runtime's `my_work_*` pilot binding is not a substitute
for the bound catalog's `project_context`.

## Preparation interface

A Python plugin registers `ctx.register_hook("prepare_context", callback)`.
The synchronous callback receives `execution` as a keyword argument and returns
`{"view": view, "rendered": rendered, "validate_configuration": validator}`.
The zero-argument validator rebuilds/checks the plugin's configuration locally
and returns literal `True` or raises a typed refusal; it performs no native
source read or publication. Runtime imports, configuration stamps and private
builder details belong entirely to the plugin. Hermes qualifies the returned
view and render, binds the proof to the capability and profile, and rejects
missing, ambiguous, changed or unloaded registrations. Publication stays in
`pre_llm_call`.

## Publication interface and timing

In the admitted worker's owning profile/capability scope, after the real
conversation turn id exists and before any provider call:

1. Read the native mission, mission authority, readonly Memory Plane and OC
   sources for the bound mission/allocation. Preserve the native OC receipt,
   freshness/selection evidence and source provenance. Produce a qualified
   `dubsar.agent-context/2.r2` mapping and its exact rendered UTF-8 content.
2. Register exactly one `cap.register_context_recheck(callback)`. The callback
   receives the same capability and returns a fresh context mapping from
   the same native sources. It must reject changed roots, identities,
   mappings, ports or authority; it must not reuse the original read.
3. Call `cap.publish_context(view, rendered, turn_id=turn_id)`. Publication
   validates identity, authority, schema/content pins, bounds and digests,
   freezes the receipt, and commits through the launcher's `_AttemptSink`.
   Conflicting publication is refused. The producer must verify successful
   publication before handing the request onward.
4. Carry the receipt's exact rendered bytes into the existing request
   assembly seam. Do not rewrite past messages, change the cached system
   prefix mid-conversation, or manufacture another user turn. The terminal
   checks the rendered content, capability and turn before dispatch.

The sink stores the execution-local `dubsar.b2b-context-artifact/1` in the
durable B2B artifact store through `b2b_commit_context`, alongside the attempt:
`attempt_id`, `run_id`, `turn_id`, original `view`, rendered text,
`context_digest`, `view_digest`, `rendered_digest`, source-basis contract and
digest. The publication destination is this host-owned store, not a managed
config file or a new network endpoint. Context is bounded by
`CONTEXT_MAX_BYTES` and the r2 render limit (9000 characters).

Rechecks occur before the provider boundary, immediately before the dispatch
CAS, and before sealing. They must finish within the sink's source-window
deadlines. Semantic source equivalence is checked separately from fresh OC
read metadata; replaying an accepted read at another boundary is not a
recheck. Errors remain fail-closed; no fallback context or provider is allowed.

## Authentication and signing

Do not invent a C1 signing key or claim that a hash is a signature. In the
current interface the context receipt and artifact are not independently
Ed25519-signed: their integrity comes from host-only capability publication,
validation, digests, durable ownership and source/CAS fences.

The source protocol is signed: Hermes signs its `bind`, `before_provider`
and `before_seal` request envelopes with the owning profile's operator-supplied
Hermes Ed25519 private key; Portal signs its response envelopes with the
Portal private key, verified against the configured Portal public key.
Those signed exchanges bind the execution authority. Native source receipt
provenance is preserved, not replaced by a fabricated Hermes signature.
Any future detached C1 signature requires a separately agreed wire contract,
signer/key ownership and verifier; it is not implemented or assumed here.

## P2 evidence and scope

The native integration lane (`tests/gateway/test_api_server_b2b_native.py`,
integration-marked, gated on `B2B_TEST_MY_WORK_ROOT`) demonstrated the original full
path in one subprocessed host: real `APIServerAdapter.connect` with the
unauthenticated model-gateway probe, real authenticated POST, Ed25519-signed
source envelopes in both directions, durable admission, plugin discovery of
the installed external producer, bound runtime composition, real My Work
mission read through `createB2BMissionPorts`, real OC kernel against
task-owned PostgreSQL (state journal + ordered projection), real `AIAgent`
construction and `run_conversation`, `pre_llm_call` publication,
source-bounded terminal dispatch CAS to a loopback provider double, and the
sealed `dubsar.b2b-proposal/1`. It also demonstrates A-B-A profile isolation
(two homes and two missions with separate native roots under the same
project label — no shared context), replay served
from durable state with no redispatch even after the Memory Plane becomes
unavailable, and fail-closed refusal before
admission for absent plugin, missing, stale, crossed and late memory
context, each leaving no attempt or binding rows and zero provider calls.

Boundaries honestly labelled as doubles: the Portal source service, the
Memory Plane v2 HTTP endpoint and the model endpoint are local HTTP doubles;
the OC authority is the fixture's simulated authority; the stdio test host
composes the production My Work ports (`createB2BMissionPorts` + bound
`handleMessage`) because the regular `hermes-mywork-service.mjs` does not
serve `mis_` B2B mission views. This is not an installed MW-O bound child,
not Portal browser proof, and not a qualification of deployment or network
policy.

Out of scope for P2 (explicitly not claimed): P3/P4 and any C1-C6 claims not
exercised here; the remainder of PR120 §5 — Portal/proposal chain, projects,
approver, mail, Composio, ticket and profile deployment, and any end-to-end
installed-environment proof; MW-O orchestration or installed-UID proof; real
model tokens or any external network; production bypass paths for legacy
tests; and any readiness claim from installed plugins, ambient capability or
operator inputs alone. Merely supplying all operator inputs or changing
health status cannot open execution — only a current, mission-scoped,
source-fresh native proof bound to the attempt's own capability can.

## Recorded verification — 15–16 November 2026 (historical, before pass 2)

Current pass-3 results are recorded in the task report and PR description; the counts below
predate the `prepare_context` interface.

Baseline: `82fee98f75a65fc508d76ef88d31fe0aa4e8a39b`. Resumed work:
`fe2a14af9bce18f8aa661936e20b7776064af8f2`. No real provider was called: the
native lane uses synthetic data and local doubles, with task-owned PostgreSQL.

| P2 proof | Result |
|---|---|
| Native tests copied onto main, production unchanged | **RED: 3 failed, 5 passed**. The nominal and two post-admission drift scenarios stop at `503 execution_unavailable`, rather than an import/setup error |
| Same native tests on P2 | **GREEN: 8 passed**. Valid publication/seal/replay across two homes; OC/config drift refuses before model dispatch; absent plugin and missing/stale/crossed/late context leave no admission |
| Execution lane, admission, runtime, terminal, hot-path isolation | **432 passed**, zero failed |

The main worktree received only the native test files and the runner's
`TMPDIR` forwarding adjustment. Each worktree used its own editable Python
environment. The corrected health test first proves that the ambient
capability is ready, then proves that health ignores and restores it.

The broad campaign used 32 **frozen** file lists, 149 files each. Every
command had `timeout --kill-after=10s 890s`, a log and an exit receipt.
The first four slices reached their time limit; subsequent slices used
three concurrent runners instead of four. Completed outputs were counted
once per file, without adding repeated failure summaries or targeted reruns.

| Broad suite | Recorded result and limit |
|---|---|
| Python | 4,757 of 4,768 selected files returned results: **46,675 passed, 61 failed, 33 pytest errors, 631 skipped, 1 xfailed**. 101 files were non-green; 59 files reported no test-count outcome. Eleven files have no result after the four timeouts |
| Python comparison to main | Same selection/markers on the 101 non-green files: **1,221 passed, 50 failed, 33 errors, 9 skipped**; 78 files also non-green on main. The other 23 files were rerun on P2: 506 passed, 3 failed, 1 skipped and one file timeout; the three remaining files then passed serially (**32 passed**). That serial comparison also reproduced the MCP watcher failure on main (**31 passed, 1 failed**). Thus 79 original non-green files were also non-green on main at least once; the other 22 passed their targeted P2 rerun |
| TUI | **1,579 passed, 1 failed**; the affected file subsequently passed **17/17 on main and P2** |
| Web | **352 passed** |
| tests-js | **46 passed** |
| Desktop Vitest | Timeout; no complete count claimed. Three printed failure files compared on main: **56 passed, 1 failed**. The Electron installation failure reproduced on main; the other two files passed their targeted P2 rerun (**56 passed**) |
| Desktop package validation | `test:desktop:all` passed with an isolated HOME; local package built and validated, no updater or application-install flow launched |
| Desktop Playwright / Rust | Blocked before executable tests: missing `libgtk-3.so.0`; missing Cargo/Rust/system build dependencies. Same host prerequisites on main |

Docker's 25 test files were excluded by the explicit no-Docker instruction.
The broad Python marker expression was `not integration and not live`;
provider/service opt-ins stayed off. P2's native integration suite was run
separately and explicitly. These skips, timeouts and prerequisite blocks are
not passes, and the broad campaign is **not globally green**. The intermittent
failures are reported without asserting that CPU load is their proven cause.
No unrelated production code was changed to make those suites green.

Raw logs, immutable file lists, baseline comparisons and count scripts are
retained in `/srv/dubsar-lots/b2b-l13-p2r/evidence/`; the final task report is
`/srv/dubsar-lots/b2b-l13-p2r/REPORT.md`.

## Vision delta for P2

| Principle | P2 status and evidence |
|---|---|
| 1 — Agent proposes | Preserved: one iteration, no tools, no recovery/fallback (`api_server_b2b_execution.py:320-334`; `agent/b2b_execution.py:627-654`) |
| 3 — No direct business action | Preserved: existing proposal-only terminal and dispatch CAS; no Tool/Composio surface added (`agent/b2b_execution.py:1185-1224`; `api_server_run_idempotency.py:445-479`) |
| 4 — Changed situation invalidates | Advanced locally: native source observation window is not renewed, and OC drift blocks dispatch (`_assert_source_window`, `_PreparedContext._assert_window`; native drift tests). Installed Core approval remains a separate qualification |
| 5 — Decisions have evidence | Advanced for context/proposal: exact render, view, digests and fresh rechecks persist with the attempt (`put_context` + `b2b_commit_context` persisted artifacts; typed durable refusal causes reach the durable attempt status; native artifact assertions) |
| 6 — Approver sees AI inputs | Exact AI input is preserved (`agent/turn_context.py:745-851`; native render equality assertion). The complete approver UI and model/token display remain outside P2 |
| 9 — One interchangeable model gateway | Existing pinned runtime and refusal of alternate routes preserved (`api_server_b2b_execution.py:247-334`; `agent/b2b_execution.py:1102-1136`). Installed G2 routing is not qualified here |
| 10 — Chosen model/data only | Configuration rejects `prepare_context` webhooks and shell hooks; owner-aware selection never calls a non-plugin producer. The real HTTP regression proves zero outbound mission payload. Native evidence remains synthetic and local; installed production network isolation remains outside P2. |
| 11 — Claims match code | Health is not mission readiness. Native tests distinguish the patched test-only external producer (positive path) from unchanged `05d7394c` or no plugin (`503 execution_unavailable`, no durable admission). Real components, doubles and installation limits are explicit; delivery of the external patch belongs to P3. |

Principles 2, 7, 8 and 12 have no changed product surface in P2. Approval,
global stop, cost tracking and the real Portal journey retain their separate
delivery/qualification requirements. This is no deployment, network C1–C6
qualification or authorization for a real model, email or GitHub business action.
