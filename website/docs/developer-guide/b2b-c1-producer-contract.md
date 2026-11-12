---
title: "B2B C1 Producer Contract"
description: "Deferred L2-mw integration and the closed B2B execution boundary"
---

# B2B C1 producer contract (L2-mw)

## Delivery boundary

L2-her does not open B2B execution. Operator files, valid schema hashes and
an inert constructor are preparation, not evidence that a context producer
is installed. Enabled lanes remain `not-ready`; complete preparation reports
`c1_producer_unavailable`. The proposal POST returns
`503 execution_unavailable` before `b2b_admit`, title changes or worker launch.
That refusal covers NEW admissions only: an already-durable attempt is always
served by the idempotent replay (`_replayed_response`) before the readiness
guard, so a lost-ACK retry recovers its run — and any error entering the
profile scope or reading the serving config still answers the same typed 503,
never an untyped 500. No attempt or binding is created by that refusal. There
is no operator flag that enables C1 in this delivery.

The future L2-mw lot must connect per-mission My Work and Operational Context
to the actual gateway conversation path. Existing plugin factory/publication
helpers and unit doubles are not proof of that integration.

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

## Gate for a later opening

L2-mw must first demonstrate the real authenticated POST, capability creation,
real construction and `run_conversation`, native per-mission source reads,
publication, bounded terminal dispatch to a loopback provider double and
sealed proposal. It must also demonstrate A-B-A profile isolation, stale or
missing source refusal, middleware short-circuit/rewrite refusal before
response intake, and that unavailable preparation does not consume admission.
No real model call is needed for this proof.

Only a separate reviewed change with that producer and evidence may remove
the current pre-admission C1-unavailable gate. Merely supplying all operator
inputs or changing health status cannot open execution.
