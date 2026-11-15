---
title: "B2B C1 Producer Contract"
description: "P2 governed context admission and the closed B2B execution boundary"
---

# B2B C1 producer contract (P2)

This is dubsar-platform PR120 (§5 P2) and task L13-D4: the *Hermes* C1 path —
governed context produced by the installed `dubsar-agent-context` plugin.
It is not the chemin-modèle C1 of §5's Portal/proposal chain. Scope reference:
https://github.com/kotnisofiane-bit/dubsar-platform/pull/120

## Delivery boundary

P2 wires the governed C1 execution path end to end — proven locally by the
native integration lane, not an installed deployment: admission now requires a
live, current, mission-scoped context preparation built through the installed
external `dubsar-agent-context` plugin — real native My Work mission reads
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
frozen policy frame and catalogue project JSON, the loaded plugin module /
manager / bound-runtime stamp identity, and the native OC `/2` source
observation —
`state_projection.candidate.result_kind == "measured"` with explicit
`source_observed_at` and a positive integer `freshness_max_age_ms`. The
source window `observed <= now < observed + min(900000, freshness_max_age_ms)`
is enforced at preparation, publication, configuration and every recheck;
its deadline is stored in the preparation and is never extended by provider
delay or another TTL. `/1` OC receipts and view/capture instants are never
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
integration-marked, gated on `B2B_TEST_MY_WORK_ROOT`) demonstrates the full
path in one subprocessed host: real `APIServerAdapter.connect` with the
unauthenticated model-gateway probe, real authenticated POST, Ed25519-signed
source envelopes in both directions, durable admission, plugin discovery of
the installed external producer, bound runtime composition, real My Work
mission read through `createB2BMissionPorts`, real OC kernel against
task-owned PostgreSQL (state journal + ordered projection), real `AIAgent`
construction and `run_conversation`, `pre_llm_call` publication,
source-bounded terminal dispatch CAS to a loopback provider double, and the
sealed `dubsar.b2b-proposal/1`. It also demonstrates A-B-A profile isolation
(two homes, two missions, two projects — no shared context), replay served
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
