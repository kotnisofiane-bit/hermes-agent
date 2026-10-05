# KOT-228 runtime overlay — Personal convergence

Source base: Hermes e9bccc90a5e314ddf6dd4bd3772d50cb40027275.
Qualified original fix: hermes-agent PR #2, merge
 d15e3714fddc7018e9b4e1993fe6af539af5bd7a into base/personal-a1-v2026-9-7.

This branch applies exactly the acquired production diff to that installed base:
hermes_cli/plugins.py, tui_gateway/methods_tools.py, tui_gateway/slash_worker.py.
All three old files are byte-identical to qualified base 109453267…; all three
new production files are byte-identical to qualified candidate c0b17d455….
No change to approvals semantics, sessions DB, model routing or the Hermes
agent engine is introduced. The other differences of the later Personal base
are not copied. KOT-228 is not reopened and Hermes main is not upgraded.

The qualification tests are the original fix's native/session/thread tests,
with no production fixture/session and no business effect. Using the canonical
scripts/run_tests.sh, per-file isolation, no credentials and zero file retries:
156 PASS across plugin/RPC/R0, plus the acquired slash-discovery regression 1 PASS.
The two native R0 cases exercise actual stdio sessions, native APPROVE/DENY
queues and resume with the same ticket/context. A synthetic unused agent
replaces the model, not the session or approval path. No live human decision.

The first local sandbox run lacked socket access and ruamel; after provision of
the isolated development environment and local socket permission, the affected
three files were rerun and all passed. No test is counted as skipped/PASS.

This source overlay performs no installation. Its separate private operator
plan requires unchanged source preconditions and preserves unrelated code,
configuration and session data, with rollback. No operational topology,
credentials or session records are exported in this qualification note.
