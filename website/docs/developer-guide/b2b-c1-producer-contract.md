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
The native positive path therefore runs against a local clone of the same
pin materialized at test time by
`tests/gateway/native_b2b/profile_fixture.py`: the fixture verifies the
versioned `dubsar-hermes-profile-prepare-context.patch` byte-for-byte by
SHA-256, applies it to a fresh local clone of the pinned checkout, and
materializes a second clean copy for the `legacy_plugin` negative case. The
patch is a test-only reconstruction authored for this harness — it does not
claim or certify equality with any external patch — and the shipped producer
at `05d7394c` keeps returning `503` until P3 delivers the real plugin change.
Only callbacks registered through `PluginContext.register_hook` count for
admission. A new attempt fails closed with `503 non_plugin_hook_subscribers`
before context preparation, native reads or durable admission if any raw
subscriber on any event lacks an active plugin registration; scope, discovery
or manager lookup errors remain `503 execution_unavailable`. The check is
repeated immediately before `b2b_admit` to catch registrations made during
preparation. Durable replays bypass this new-admission gate. The producer's
own plugin must also register `pre_llm_call` under the same owner as
`prepare_context`.

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
(`execution_inputs_unavailable`, `c1_producer_unavailable`,
or `c1_context_required`) — health evaluation
performs no plugin discovery or
probe and cannot leak ambient execution state. A NEW admission whose
preparation cannot produce a qualified source fails closed before admission
with a typed 503 whose `error` and `code` carry the same reason. Every typed
preparation refusal raised inside the bounded preparation answers `503
execution_unavailable` — an absent producer, a missing OC receipt, a `/1`,
non-measured or otherwise unqualified receipt, a captured rather than
observed instant, a crossed or stale memory-context read, a render/bounds or
schema/contract refusal, configuration drift, or any other
`B2BTerminalRefusal` — and so does any untyped exception there
(`gateway/platforms/api_server_b2b.py:1371-1375`). The only cause `_prepare`
does not rewrite is `context_oc_source_stale`, relayed verbatim: host code
raises it at exactly three sites, all reachable before admission:

- the `/2` projection's age/instant coherence, checked by
  `_native_oc_read_metadata` (`agent/b2b_execution.py:225-229`) from
  `qualify_context_view` (`agent/b2b_execution.py:826`) and again from
  `_prepare_b2b_context` (`gateway/platforms/api_server_b2b_context.py:324`):
  a non-integer `age_ms` or `freshness_max_age_ms`, an `age_ms` unequal to
  `view_instant - source_observed_at` (an incoherent receipt, not a window
  question), a negative `age_ms`, or `freshness_max_age_ms < age_ms`;
- the observation window `observed <= now < observed +
  min(900000, freshness_max_age_ms)`, checked by `_assert_source_window`
  (`gateway/platforms/api_server_b2b_context.py:200-209`, called at
  `_prepare_b2b_context:350`): a source dated in the future or older than its
  governed bound;
- the stored `source_deadline_ms`, rechecked on the host by
  `assert_context_source_current`
  (`gateway/platforms/api_server_b2b_context.py:212-216`, called at
  `_prepare_b2b_context:361`, at `gateway/platforms/api_server_b2b.py:1367`
  after the readiness classifier, and at the admission gate
  `gateway/platforms/api_server_b2b.py:1440`): a deadline that elapsed while
  the preparation or its validators ran.

`_prepare` relays that literal cause unchanged, so a producer or validator
that raises it is answered the same way
(`gateway/platforms/api_server_b2b.py:1371-1373`). The readiness classifier
consulted at the end of preparation can also answer its own code
(`execution_inputs_unavailable`, `c1_producer_unavailable` or
`c1_context_required`, `gateway/platforms/api_server_b2b_execution.py:164-183`)
when the inputs, the producer registration or the attached preparation are no
longer current at that instant for a reason other than the OC deadline — that
deadline is rechecked immediately after and wins as
`context_oc_source_stale`
(`gateway/platforms/api_server_b2b.py:1365-1375,1403-1404`). A bootstrap or
preparation worker that misses its budget answers `execution_unavailable`
too. Those refusals cover NEW admissions only: an already-durable
attempt is always served by the idempotent replay (`_replayed_response`)
before the readiness guard, so a lost-ACK retry recovers its run — and any
error entering the profile scope or reading the serving config still answers
the same typed 503, never an untyped 500. No attempt or binding is created by
that refusal.

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
bound is never renewed. `assert_context_source_current` re-proves the attached
preparation's `source_deadline_ms` on the host — pure timestamp arithmetic,
never a plugin callback — after the last plugin validation and immediately
before each of the four commit gates: launch admission (before `b2b_admit`,
answering `503 context_oc_source_stale`), context publication (before
`b2b_commit_context`), the dispatch CAS (before the paid provider request) and
the seal commit (before `b2b_seal`). Every gate raises the typed
`context_oc_source_stale`; the CAS and seal gates also record the durable
`context_stale` classification. An observation that crosses its own bound
during final validation, host serialization or across the host-resume seam
therefore refuses instead of admitting, publishing, dispatching or sealing.
Typed preparation refusals reach the durable attempt classification without
being replaced by a fixed `context_unavailable` reason.

Every B2B plugin operation in the launch and seal path runs inside its own
daemon worker under `copy_context`, off the asyncio loop and off the
loop's default executor, under an explicit per-request deadline judged on
the worker's own finish instant: the bootstrap (secret-source hydration,
gateway config, plugin discovery — `_REQUEST_TTL_S`), the native
`prepare_context` read (`_SOURCE_DEADLINE_S`), and the seal-time
recheck/source/policy validation. A request whose worker misses its
deadline is refused — that request alone — and the daemon is never killed:
its late result is discarded when the worker finally exits and can mint no
durable artifact. There is no cross-request accounting: no abandoned
counts, no stuck health state, no single-flight admission, and no new B2B
capacity gate — siblings on one home bootstrap and prepare concurrently.
The inherited generic API admission (`gateway.api_server.max_concurrent_runs`, the same
`429 rate_limit_exceeded` the other run routes apply) still guards a NEW
attempt at its original place, after bounded preparation and before the
signed-proof freshness recheck and durable admission; a durable replay
bypasses it exactly as it always has. Known limitation: plugin discovery
runs before the native source deadline starts, bounded only by the
per-plugin loader timeout (10s), so a producer that is slow to discover
delays every attempt's first read without tripping any preparation bound;
no code extends that timer.

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

## Deferred scope (P2-cap)

Removed from this change and explicitly deferred — none of these exists in
the current lane:

- **Bootstrap stuck health/recovery.** No `context_preparation_stuck`
  health code and no health-side recovery for a bootstrap that outlives
  its bound; the timed-out launch is refused and its worker's late result
  is discarded.
- **External `API_SERVER_KEY` recovery after hydration failure.**
  Secret-source hydration that fails inside the bounded bootstrap refuses
  that launch; recovering external key state is not revisited here.
- **Expired-turn qualification/classification.** Turn-window expiry during
  dispatch/finalization keeps its existing refusal classification; a
  distinct qualification lane is deferred.

## Recorded verification

Measured results for this pass are recorded in the task report and PR description (bounded runs; raw logs, commands and counts are kept in the lot evidence directory). The stale pre-pass-2 tables that used to live here were removed rather than re-stated.

## Vision delta for P2

| Principle | P2 status and evidence |
|---|---|
| 1 — Agent proposes | Preserved: one iteration, no tools, no recovery/fallback (`api_server_b2b_execution.py:320-334`; `agent/b2b_execution.py:627-654`) |
| 3 — No direct business action | Preserved: existing proposal-only terminal and dispatch CAS; no Tool/Composio surface added (`agent/b2b_execution.py:1185-1224`; `api_server_run_idempotency.py:445-479`) |
| 4 — Changed situation invalidates | Advanced locally: native source observation window is not renewed, and OC drift blocks dispatch (`_assert_source_window`, `_PreparedContext._assert_window`; native drift tests). Installed Core approval remains a separate qualification |
| 5 — Decisions have evidence | Advanced for context/proposal: exact render, view, digests and fresh rechecks persist with the attempt (`put_context` + `b2b_commit_context` persisted artifacts; typed durable refusal causes reach the durable attempt status; native artifact assertions) |
| 6 — Approver sees AI inputs | Exact AI input is preserved (`agent/turn_context.py:745-851`; native render equality assertion). The complete approver UI and model/token display remain outside P2 |
| 9 — One interchangeable model gateway | Existing pinned runtime and refusal of alternate routes preserved (`api_server_b2b_execution.py:247-334`; `agent/b2b_execution.py:1102-1136`). Installed G2 routing is not qualified here |
| 10 — Chosen model/data only | New admission is refused with `503 non_plugin_hook_subscribers` before preparation, native reads and durable admission if a raw callback on any event lacks an active `PluginContext.register_hook` registration; discovery/scope/lookup errors fail closed with `503 execution_unavailable`, and the check repeats immediately before `b2b_admit`. Durable replays bypass this new-admission check. The bound-execution dispatch filter remains a second barrier for sync/async/queued delivery, with queued workers rechecking callback identity before invocation (`gateway/platforms/api_server_b2b.py`, `hermes_cli/plugins_dispatch.py`, `agent/plugin_stream_hooks.py`; `tests/gateway/test_api_server_b2b_hook_admission.py`, `tests/agent/test_b2b_hook_isolation.py`). This is not global network isolation or a constraint on arbitrary Python plugin code. |
| 11 — Claims match code | Health is not mission readiness. Native tests distinguish the patched test-only external producer (positive path) from unchanged `05d7394c` or no plugin (`503 execution_unavailable`, no durable admission). Real components, doubles and installation limits are explicit; delivery of the external patch belongs to P3. |

Principles 2, 7, 8 and 12 have no changed product surface in P2. Approval,
global stop, cost tracking and the real Portal journey retain their separate
delivery/qualification requirements. This is no deployment, network C1–C6
qualification or authorization for a real model, email or GitHub business action.
