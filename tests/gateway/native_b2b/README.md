# Native B2B P2 harness fixtures

Host composition used by `tests/gateway/test_api_server_b2b_native.py`
(integration-marked). Everything the lane needs is provisioned OUTSIDE the
tests — the tests download nothing and spawn no package manager.

## Pinned checkouts

| Role | Path key | Pin |
|---|---|---|
| My Work | `mywork` | `526f2c76` (`dubsar-my-work`, deps linked per its `deps.lock.json`) |
| Contracts | `contracts` | `9044b1b1` (`dubsar-contracts`; the OC kernel fixture `git rev-parse`-verifies this exact HEAD via `OC_CONTRACTS_CHECKOUT`) |
| Producer profile | `profile` | `05d7394c` (`dubsar-hermes-profile`; supplies `plugins/dubsar-agent-context`, `profile-mappings.json`, the `2.r2` contract root) |

## Runtime file

`$B2B_TEST_MY_WORK_ROOT/.p2-native-runtime.json` — exact keys:

```json
{"mywork": "<abs path to the pinned My Work checkout>",
 "contracts": "<abs path to dubsar-contracts @ 9044b1b1>",
 "profile": "<abs path to dubsar-hermes-profile @ 05d7394c>",
 "node": "<abs path to a Node >= 20 executable>",
 "pg_bin": "<dir containing createdb/dropdb binaries>",
 "postgres_url": "<admin DSN, e.g. postgresql://postgres@127.0.0.1:PORT/postgres>"}
```

## Provisioning (external to the tests)

- PostgreSQL: a task-local instance (portable binaries, `initdb -A trust`,
  `pg_ctl -o '-h 127.0.0.1 -p <random>=20000'`). The test only calls
  `createdb`/`dropdb` for a fresh per-case database; it never queries a
  shared database.
- My Work checkout: full clone at the pin with its `deps.lock.json`
  package links resolved (Contracts at `9044b1b1`, operator-core and
  personal authority pins). Node 24 used here; the fixture only requires a
  Node able to run the pinned source.
- `kernel_host.mjs` sets `OC_CONTRACTS_CHECKOUT` from `contracts` and starts
  the real `tests/fixtures/mw-o-oc-kernel.mjs` (Contracts kernel + PG
  migrations + ordered state projection; SimulatedAuthority is the
  disclosed trust double), then the real release-helper over a Unix socket.
- `mcp_host.mjs` composes the production ports for the stdio MCP server:
  `createB2BMissionPorts().buildMissionContextView` for the mission view
  and `handleMessage{trustedOcBinding}` for OC receipts. It is a test
  composition adapter, not an installed MW-O bound child — the regular
  `hermes-mywork-service.mjs` does not serve `mis_` B2B mission views.
- `make_store.mjs` mints synthetic mission fixtures via the real
  `sealB2BMissionAuthority` (disclosed test setup, not a production bypass).

## Run

```bash
B2B_TEST_MY_WORK_ROOT=<dir containing .p2-native-runtime.json> \
TMPDIR=<task tmp> \
timeout 1100 scripts/run_tests.sh -j 1 --file-retries 0 \
  --include-integration -m 'integration or not integration' \
  tests/gateway/test_api_server_b2b_native.py
```

`-m 'integration or not integration'` is required: the repo `addopts`
deselect `integration`, and the runner forwards the flag through.

The A-B-A profile case runs authenticated executions under profile A and
profile B, then replays A — replay is served from durable state with zero
provider redispatch, not a third execution.
