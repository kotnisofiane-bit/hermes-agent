"""H1 test harness -- REAL process glue.

The doubles are: a Node control surface (never touches P1 code), a loopback
provider double with a durable journal, and an explicitly labelled UNIT CONTEXT
PRODUCER/RECHECK double driven by the frozen template. Everything under test is
the genuine P1 Portal bench (native JWT/session, MongoMemoryServer, pinned
MyWork, real L2a bridge) and the genuine APIServerAdapter child process.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
import zlib
from typing import Any, Dict, Optional

# Lead-provided r2-*.json bytes from Contracts 2b0865261e80432103e6beb38e5beea0ce60dad0
# (zlib+base64 embedded; SHA-256 pins verified on extract).
R2_SCHEMA_B64 = {
    "agent_context_r2.schema": "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",
    "mission_binding.schema": "eNrtWM1v2jAUv/evsKIe9kESwugHXCpNO27aDpt2KBSZxAF3iZ3ZDh1C/O+zEyc4IVBI0dRO5ZL4+X0/v98zWZ0BYJ1zf45iaA2BNRci4UPXveeU2DnZoWzmBgyGwu11e13b67mav5MJ48AU9CkRDPqCO0E65ZA5mCxghAMXzhARttpGf4S76Lkx5hxLK1NMAkxmjramLOeaBRYRUrq1pooGpybuetodn8ax5FNy3xi9R76QXICGQAsAHMhtLJYOgKmYUyZfJwGeIS4AQyFiHAgKvizBT8p+OeD7HHNAp0oPkG+ECgAJQGGoCKUCR3u8TDKHc/6cBoMAKxdgJN1JEBMYcckTwoijjIGh3ylmSGXxVq4lJaQshrm4XHEBRcqLVZLHNJFZ1xQdl0FhaIEVqVhPIcdcx1jQ6rGX1nzpZLGQmlPEyi2aMh9VV5Oi3jWyVipp4yzIxIx9VQmzWEuKVMbFERXP5NbVPBnqEEljlVVrRheIEZniDrAiNIP+cpKSKU1JRkkJXEAcwak8bZ0sn9Itf26NK+qNxBsmIFl+DcvKqd+qfDMOBBdMeqxzpPdiTD4jMhNzyeBVd+CfcueyX9lKoBAyFKXz7s3N8PZuNOKjUdqVPzt/XuePaf7w8wfKN71w/FZLHSHyroWVm3OrdHu9iWC1SQlJo8gCa71VzbVxpP9lrr3e9c5k13ImY3z/pBDLHt0f4EYZlk0wU82YRYPj7Gh7nSwCvRp0u1feYNC76F/1u4OB18KtClQc6lqR8WrG+Bz2Li6Ht117AO1wvLrsr8+tFi5tIdXzcCsHysd8KRFNoh9XQ8COqA+jNgY1GB9sMcdQO17aD3KStQoxB/wmRI2XE6V1UnRqWSQDYiVihjhCkxgmiS4EoQRZTUY2c+TI+Bwdn11MhwVGD3I0tA73NKes/fE60w5ZMlWG1dKZhklaG39GjsrBZ3rQPMpe51UDmNcm0WNV//Tjo60qP159qFW9gvcnA/UtuH4y+DWi7dO1lmB5GCIaWHcYoBlQZQjsBqkG2QoCtYKZbQA5FiW0qrUJS+0av3bLfW3/U7T/M7xt1nClqL+aLI8AxU7WZgTYyd7Q2ls8Te28raiphXdcJQ7v3x1m9sR2uiY0/1ju6cA9ztbHz07G//wYZPfGl1H08vPBa8VfUMXVh6qz9dlfakfM1g==",
    "my_work_mission_authority_view.schema": "eNrNVU2P2jAQvfMrrGiPmIR0PxSkXtpeq/ZS9bCiqyFxgreOndoOuxHiv9dOnBAgsCz0UC7I45l5z2/mwXqEkHej4iXJwZshb6l1oWa+/6wEx014ImTmJxJS7YdBGOBp6Lv8cV1Mk35hLLiWEGs1ScqFAjmhfAWMJj5khGtsr8mr9lehn1f4RcjfOKdKUYMGpV4KSXWFV5S8TBy4JdIAaaoZsVCu8el6f+roxSLPDbIt/MyEIgkqpHgmsTY1SKRILwn6WqGfphWqgRGsgDJYUGZ6feSCE0QVgoUiPCZjxIVGkqyoxUQBAp7UIUCMZBBX3d3Esa6KmrRYWMwmBklCLTyw71IURGpKlMlJgSlSJ0jyp6SSWGEfzdlEUiFzaMptgx7DNuZkeDLjcJGWSXtegKLqKaEZUdtOrWh7cRUbYu3BdC6J9MxhXtMr+qzXOwTNGXlmyEq/Z1JoM/SwuhfhZW5laK/MCoyRZ6fizbuy3ttbQrYZr76lnYT2s97OQ2lJeWZ7FaA1kdwGf3358Qk/Bjiarz9sbjpae6W8ZMzcuat5/b3Z1/xcHtT4ITPiju0rOM3r107tCV7dKQqCh2kUhXe3D7dBFE0voLUz+uskUksI7+5nViXA6Xx9f3uZUgeb93/Qahb/LS7dhhsfKGtkzEQM7BJAZ66zERtPYeepdyGOHKpn3NND6IAHfH3ElR2brSv7RPYMebnrdvz0z0xzYIerl2twm6/v2i3jeRvX26VTC+PyN/01vGYH6h/jk+NvU+1Wnhjv0bTDeR1NHR7E0fQBhQ9yhlRtknaVtP+Po83oL3A3oJQ=",
    "my_work_mission_view.schema": "eNrNV0tv4zYQvudXEKpvtSxbSQOsbrvtpUAX7aEPoIFr0NJY4q4kqiTltRH4v3f4kmTHUbJeB+jJ4mO++fjNcDh+vCEkmMi0gIoGCQkKpRqZRNEnyevQTs+4yKNM0I2K4nk8Dxdx5PZPjTHLhoYpr5WgqZKzrF1LKmas3tKSZRHNoVahXoadirZxVO3DL1x8DismJUNvWwZfZs6ldm/hFVMlaAcO7pxVtHBUUl5V6EVvf6/d/Wi9kW1MaJpCo2idAuEbogogH/fkL0QiHy0S+RORpoTVadlmrM4JU5IIoCVxrla0VQUXTO1JI/gnSBVOzsjvCLVdEEucMEnaOi1onUM2cyfYN+YAfK1t7BzNMqbNafmb4A0IxUDing0tJZgNAv5tmQAt7UOw4aKiaBnQLWUlXbMSSeDQ0VhhBKaBZ2kGiqWfwS1oueyXVFSBWdWaTh0jttXfKR4MBMOgBuuSo7XALwEbEICaSTNouGSKC+0adpC2+gQr3KNXYcsyvdOPn4iGcyWrUFRNQKBIyMWQ4q1As4zlIFWwNKdvhqI84gzOORFwHGASSfVyThym1vJINW0PdVsZYd2KEcMY1zl+tXU/v/QgA601hA+qVMIaVaz+BepcFUGywBHd+dH9nYcYREhD0Hr/6yZIHjzYK7Bu5/PDtNtft2UZHDqGfczH0RuqMNI1Tv3z0x8fwod5+G75eHuYBM9D+xR6C9o2KS9E1uI+r4etHBcBL+5HKPf35lL0+Zgi3VXsEy2gQlB9hRDkZwUV3ot4Pg2Y/fzKUHg//p6/RVQHleONTzEoS75WdEW3q7nPFNyu3jokX3MfBqirVpS2dqJRna9kQV1RlQ3V9Y5z7WAt8G0pTFG2RcxXjc6Z53bE2aAnF+kfjyWRv1o95+SVNUHXAxpulo9387Ga0NWFgQqXneNu/u5+3I3TNrl6mroYXRXZAdtfn6Qnz+WFiXqUoWkrJNePdMoz2GnLVnF8IdH25QR0xkfnniA1ZPJdNMmQY+S2jGtnfY/CmB3jKAPmycm+82oe9RrJm5aXp32Mrmf2kLh60nl0u552sx7QNUFjrG/jAesTPY150NHrO6kecM15CbT3eNxhJa+7/fiyToz8B9taZ1bqwRkGSBdkL6YF7s9AYaeF+XqcqHb5Babvw7+R7Gr5/SQ4ip6uJh74a6Ie/3B/6HTtL8jFRzR/eGzjjUHqO/BWmlZ4A+k+1R3m6dk7u6vWO8/huqDuPMkVm7eBNFeE7QPrK9Y3pe5uJWHwd6sAkYmTCMOOqZXJ47PZfYRw3aB0bP7/se5FOgfL8N97DmffoIMpTTeHm/8A43VziA==",

}

R2_PINS = {
    "agent-context-r2.schema.json": "8615f3b4730acbabc614cd7cc770730be244888b59cc69957f14d4f520dbd0e2",
    "mission-binding.schema.json": "919264ea23b6ef458a8fa5ac49769c2a11fc2dcf5bedbefac30ce56d0d2aab16",
    "my-work-mission-view.schema.json": "3a8c7eb91e88b3ce0f92335a6bf91731d96a925648351f3187fd30b71621d9fa",
    "my-work-mission-authority-view.schema.json": "e33b996a46fcc77ce71282140ecf8e9e166d5da2566da355c94a9fa026551933",
}

_SCHEMA_FILES = {
    "agent_context_r2.schema": "agent-context-r2.schema.json",
    "mission_binding.schema": "mission-binding.schema.json",
    "my_work_mission_view.schema": "my-work-mission-view.schema.json",
    "my_work_mission_authority_view.schema": "my-work-mission-authority-view.schema.json",
}

# Frozen lead-authored UNIT CONTEXT template (H1-CONTEXT-DOUBLE-TEMPLATE.json),
# zlib+base64 embedded. Transformed per execution -- never a C1/AgentContext build.
CONTEXT_TEMPLATE_B64 = "eNq9WFlv4zYQft9fIeg5cmS5tmO/dZM8FCiSYpEARRcLgaKomDVFqiTljbvIf9/hocOWryJIjQCJZzic++NMfnwKgrAQskQ6XAZhXmcKyRF6IVxHWHBNXvV1MpJJeGUOrinPzTHLTz0/3VDy3fFRrVdCUr01h7jgxJHJK8G1RhkjQC8QU8SSrTzco2WtrHaUb6gScpvmSCMnahVIYSXDHlmCJqdEp4owgjXJHQujSteS5KnzKImTWTSOo2TxFMdL+zOK4/ivsDMBNOT0hTgbSEGS8XyG5jckiefJJMvyxWxyUyzQbDJd/DKdTpMco1kynsxjNCeLKcmyKb7BNyBSTBNvXwZmURsq+MuRKikKyogn56RANfOskipFBfesu+fPURyPW6m/wTnPMt8itCuUQU4ofwH2DyCfzebIy0Ve7topAjmlka6VkXsRGyK5D+gpI07aDkxJIKHABdbYkzKkqOrFW61QMp0ts3d+Go1tBQ5VoHd+2jhhUdlyrIhUgiMWMYERa9gQj5rILvxRuY2+C7luxUUtsZUvt6lhpE0Iu+7ZOWr7TCLcT6m/M2qSaVqwl0kn10WgeOcnhHvfbNXRHGrJhPdSN8IS8RqxdE22Kq0VyXcgQBIlWK1dibR1l2ai5r6d7YkN0AqBa2WusTqdruVOr7RHVZ3ZevWHffku+93DUUlUhTBRAB9I4pU17GvIVfht/4AkhTf8q+OVpASU6joOVdTo2SRtFW4QZSijzEOh/85Ic6AAW1ecKNtuuJYSonoi605hVDHEyWiTXPtejlrk7TXiPxBtWlCMmqh6QtfOx5DjTDcf7OcPbjmr461FE2adUm0mPIJLlFPccFpfyAaxuo0CJL9CL0i3YbAXYiHz/nVAFCXVcColPK8E5dqw45abwzWVrYV4xzZ4kDi2t/fKG+ibcQpfWYbweo/DKChyutvu8q3Uq6z3F5JtLKLb9vS1816MOeZwz63dcuunZvBEndR1QRxOP1LnC1tTvCb6GNfCm+PVnOooFzWo7qO6fz5tsLXIRf9m7YaXp44mLDzRjaU/dnQMXUQkRRaJcNjVZAYvzNo+KrxmrFe/BYGEA0ZZiYK+msln2QT8W+9gJRTVfdDao6e1ZHvXO5+kBohIoZ+HXOO/hUgY0IQe8jOJOF4N6VXjiCe9tXa6QdHkCVxTu7ZCccNsOLwNi5y8DsmASqJsuv+wso15zIz1TlcPA4ZP2Y4pZ8u3ldsv5ItK+Wy5HkHiD5+u/qcJ64Ip6/SkNUj1AJSOA9hHjU9gTgvz4Jm0pQlzUQPHHwH5Ag93tIsgX+BmXYgkQfl51LfX9wD+XWBsLkspB/Dh51c4KwFboMXA8Pnht6fg9vHh6f7Pp+CPL493z7f3X4K7x+fPv9+PggcR/Gp2oVvnW5DVlOVEBkIGLiaBInJD4TdVAWCRxBTmvtHuFHLo3UYYk8oMDYNsnlnGGsF21x4fGyHNoouqisFg16uFi554P+ftPMrNlINh0tbdhPMfnvXDu/7Bbb+NEzYDPkSgi0+3dGJRVozozjW71Rt3SgKa8t7Y3+FyaspTcLZNKyHBvmYoRJULHfVPo5/Yr7oR6+pwG3Y53fM4tDtJ9ybBBl/Zf0E0i22JXtNDtP7UmsQ7DA7Fl+IVkoa3gJLucZUZBBj912xDW1fdk2Q+u2nyJ0HWDe9uJmn6FXotrzGRfkgJ92bnQcL3rJhP2/AP9c8ncxOeT2+ffgI8RYqU"
CONTEXT_TEMPLATE_SHA256 = "6738ecbf55d33e9af000f3c5e6b3924fcdd27cac47679e2d5d3601156180a7fc"

# Exact lead-authored fixtures -- do not paraphrase.
UNIT_RENDERED = (
    "UNIT CONTEXT PRODUCER DOUBLE. Synthetic data only; no AgentContext builder.")

MISSION_FIXTURE = {
    "title": "UNIT H1 mission \u00e9 \U0001f600",
    "objective": "Prepare a synthetic non-executing proposal.",
    "criteria": ["No approval or business execution."],
    "source_refs": ["fixture:h1"],
}

PROVIDER_FIXTURE = {
    "summary": "UNIT PROVIDER DOUBLE: synthetic non-executing proposal.",
    "steps": ["Read the supplied synthetic context."],
    "source_refs": [],
    "limitations": ["UNIT CONTEXT PRODUCER DOUBLE; not AgentContext/C1 qualification."],
}

DOMAIN = b"dubsar.b2b-source/1\x00"
VERSION = "dubsar.b2b-source/1"


# ---------------------------------------------------------------------------
# Fixtures / crypto helpers
# ---------------------------------------------------------------------------

def extract_contract_root(tmpdir) -> str:
    """Write the four pinned schemas to *tmpdir*/contracts, verify each SHA-256 pin."""
    root = os.path.join(str(tmpdir), "contracts")
    os.makedirs(root, exist_ok=True)
    for name, b64 in R2_SCHEMA_B64.items():
        raw = zlib.decompress(base64.b64decode(b64))
        filename = _SCHEMA_FILES[name]
        assert hashlib.sha256(raw).hexdigest() == R2_PINS[filename], filename
        with open(os.path.join(root, filename), "wb") as fh:
            fh.write(raw)
    return root


def context_template() -> dict:
    raw = zlib.decompress(base64.b64decode(CONTEXT_TEMPLATE_B64))
    assert hashlib.sha256(raw).hexdigest() == CONTEXT_TEMPLATE_SHA256
    return json.loads(raw)


def make_keypair():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat)
    priv = Ed25519PrivateKey.generate()
    pem_priv = priv.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    pem_pub = priv.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pem_priv, pem_pub


def canonical(value) -> bytes:
    from agent.b2b_execution import canonical_json
    return canonical_json(value)


def _sig(envelope: dict, priv) -> str:
    from agent.b2b_execution import canonical_json
    unsigned = {k: v for k, v in envelope.items() if k != "signature"}
    return base64.urlsafe_b64encode(
        priv.sign(DOMAIN + canonical_json(unsigned))).decode().rstrip("=")


def attempt_id_for(binding_digest: str) -> str:
    return "b2bp_" + hashlib.sha256(canonical(
        {"format": "dubsar.b2b-proposal-attempt/1", "binding_digest": binding_digest,
         "operation": "proposal-v1"})).hexdigest()


def build_context_view(policy: dict, source_body: dict, *, mode: str = "valid") -> dict:
    """Transform the frozen template into a per-execution r2 view. UNIT CONTEXT
    PRODUCER DOUBLE data -- never a real AgentContext/C1 build. *mode* selects the
    rejection family (namespace/authority/availability/view_instant drift)."""
    view = context_template()
    mission = policy.get("mission_request") or {}
    project = policy.get("project") or {}
    view["bot_id"] = project.get("bot_id") or view["bot_id"]
    view["profile_id"] = policy.get("profile") or view["profile_id"]
    view["project_id"] = policy.get("project_id") or view["project_id"]
    view["mission_id"] = policy.get("mission_id") or view["mission_id"]
    # mission_binding mirrors the policy/project catalogue + source digests.
    binding = view["mission_binding"]
    binding["project_id"] = policy.get("project_binding_id") or binding["project_id"]
    binding["mission_id"] = policy.get("mission_id") or binding["mission_id"]
    binding["revision"] = policy.get("mission_revision") or binding["revision"]
    binding["basis_digest"] = policy.get("authority_basis_digest") or binding["basis_digest"]
    binding["authority_digest"] = policy.get("authority_digest") or binding["authority_digest"]
    binding["source_digest"] = source_body.get("mission_source_digest") or binding["source_digest"]
    # my_work mirrors the authority triplet; mission content from the bound request.
    my_work = view["my_work"]
    my_work["project_id"] = policy.get("project_id")
    my_work["mission_id"] = policy.get("mission_id")
    my_work["ticket_id"] = policy.get("mission_id")
    my_work["mission"]["title"] = mission.get("title")
    my_work["mission"]["objective"] = mission.get("objective")
    my_work["mission"]["criteria"] = mission.get("criteria") or []
    my_work["mission"]["references"] = mission.get("source_refs") or []
    my_work["mission_authority"]["basis_digest"] = policy.get("authority_basis_digest")
    my_work["mission_authority"]["authority_digest"] = policy.get("authority_digest")
    view["resolved_focus_key"] = f"{policy.get('project_id')}/{policy.get('mission_id')}"
    view["resolved_subject_key"] = policy.get("requester_id")
    view["namespaces_searched"] = list(
        (project.get("allowed_namespaces") or []) or view.get("namespaces_searched") or [])
    if mode == "namespace_drift":
        view["namespaces_searched"] = ["outside-the-catalogue"]
    elif mode == "authority_drift":
        view["my_work"]["mission_authority"]["authority_digest"] = "sha256:" + "0" * 64
    elif mode == "availability_drift":
        view["my_work"]["availability"] = "missing"
    elif mode == "view_instant_drift":
        view["operational_context"]["view"]["view_instant"] = "1970-01-01T00:00:00.000Z"
    return view


# ---------------------------------------------------------------------------
# Node P1 bench glue -- genuine production services, real native auth/Mongo/MyWork,
# real compiled L2a bridge pointed at the REAL native HTTP listener. The ONLY
# test surface is /_ctl; source requests may be journaled or RE-SIGNED into
# malformed variants, but every signed byte is real crypto.
# ---------------------------------------------------------------------------

P1_BENCH_JS = r"""
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const fs = require('node:fs');
const Module = require('node:module');
const { generateKeyPairSync, randomUUID } = require('node:crypto');
const { pathToFileURL } = require('node:url');

const ROOT = process.env.P1_PORTAL_ROOT;
// tmpdir sits outside the Portal tree -- external deps resolve by absolute path.
const esbuild = require(path.join(ROOT, 'api', 'node_modules', 'esbuild'));
const MYWORK = process.env.P1_MYWORK_ROOT;
const S = (p) => path.join(ROOT, 'api/server/services/dubsar', p);
const kp = () => generateKeyPairSync('ed25519', {
  publicKeyEncoding: { format: 'pem', type: 'spki' },
  privateKeyEncoding: { format: 'pem', type: 'pkcs8' } });
const compile = (code, name) => {
  const m = new Module(name, module); m.filename = name;
  m.paths = module.paths; m._compile(code, name); return m.exports; };
const readBody = (req) => new Promise((r) => {
  let b = ''; req.on('data', (d) => (b += d)); req.on('end', () => r(b)); });
const json = (res, code, obj) => {
  res.statusCode = code; res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(obj)); };

(async () => {
  const realConnect = net.Socket.prototype.connect;   // BEFORE bench patches it
  const portal = kp(); const hermesHub = kp(); const hermesMemory = kp();
  const { startB2BBench } = require(S('b2b-missions.bench.js'));
  const bench = await startB2BBench({ myWorkRoot: MYWORK, port: 0 });
  // Profile assignment: alpha/revoked -> hub, beta -> second (lead-settled).
  for (const b of bench.config.bindings)
    b.agentProfile = (String(b.userId) === String(bench.credentials.beta.user))
      ? 'ci' : 'hub';
  await bench.unconfigure(); await bench.reconfigure();
  // Widen the bench socket allowlist ONLY for the real native listener (set later).
  let nativePort = 0;
  const benchPatched = net.Socket.prototype.connect;
  net.Socket.prototype.connect = function (...args) {
    const input = Array.isArray(args[0]) ? args[0] : args;
    const first = input[0];
    const o = typeof first === 'object' ? first : { port: first, host: input[1] };
    if (!o.path && String(o.port) === String(nativePort) &&
        ['127.0.0.1', 'localhost', '::1'].includes(o.host ?? 'localhost'))
      return realConnect.apply(this, args);
    return benchPatched.apply(this, args);
  };
  // Real compiled L2a bridge -- refuses until the native port is set.
  let realBridge = null;
  const bridgeBundle = await esbuild.build({
    entryPoints: [path.join(ROOT, 'packages/api/src/dubsar/personal/bridge.ts')],
    bundle: true, platform: 'node', format: 'cjs', write: false,
    packages: 'external' });
  const { createPersonalBridge } = compile(
    bridgeBundle.outputFiles[0].text, __filename + '.bridge');
  const proxy = new Proxy({}, { get: (_, prop) => {
    if (!realBridge) throw new Error('bridge not configured');
    return realBridge[prop]; } });
  const { getB2BMissions } = require(S('b2b-missions.js'));
  const { getB2BAgentSessions, composeB2BAgentSessions } =
    require(S('b2b-agent-sessions.js'));
  const { getB2BAgentProposals, composeB2BAgentProposals, COLLECTION: PCOL } =
    require(S('b2b-agent-proposals.js'));
  const { composeB2BAgentSource } = require(S('b2b-agent-source.js'));
  const mongoose = bench.mongoose;
  await composeB2BAgentSessions({
    collection: mongoose.connection.collection('dubsar_b2b_agent_sessions'),
    missions: getB2BMissions(), bridge: proxy });
  const proposals = await composeB2BAgentProposals({
    collection: mongoose.connection.collection(PCOL),
    agentSessions: getB2BAgentSessions(), missions: getB2BMissions() });
  const sourceComposition = await composeB2BAgentSource({
    config: { enabled: true, port: 0, portalIssuer: 'portal-h1',
      privateKeyPem: portal.privateKey,
      profiles: [
        { profile: 'hub', hermesIssuer: 'hermes-h1-hub',
          hermesPublicKeyPem: hermesHub.publicKey },
        { profile: 'ci', hermesIssuer: 'hermes-h1-ci',
          hermesPublicKeyPem: hermesMemory.publicKey } ] },
    mode: 'bench', missions: getB2BMissions(),
    agentSessions: getB2BAgentSessions(),
    proposals: proposals.runtime });
  const source = sourceComposition.runtime;
  // Journal + fault-injection on the REAL signed-source path.
  const journal = []; const faults = { mode: 'none', mutate: null };
  const origResolve = source.resolveSignedSource.bind(source);
  source.resolveSignedSource = async (...a) => {
    journal.push({ at: Date.now(), purpose: a[0]?.body?.purpose, req: a[0]?.request_id });
    return origResolve(...a);
  };
  // Test-only control surface -- never a production route.
  const ctl = http.createServer(async (req, res) => {
    try {
      const body = JSON.parse(await readBody(req) || '{}');
      const url = req.url;
      if (url === '/_ctl/set_bridge') {
        nativePort = body.port;
        realBridge = createPersonalBridge({
          baseUrl: 'http://127.0.0.1:' + body.port + '/v1',
          apiKey: body.hub_key,
          profileApiKeys: { hub: body.hub_key, ci: body.ci_key },
          timeoutMs: 1500 });
        return json(res, 200, { ok: true }); }
      if (url === '/_ctl/mission') {          // REAL native route -- no hand insert
        const r = await bench.request('/projects/b2b-bench/missions',
          { scenario: body.scenario || 'alpha', method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: body.body });
        return json(res, r.status, r.data); }
      if (url === '/_ctl/agent_session') {
        // Native L2a POST carries NO body -- any content-length => NO_PARAMETERS.
        const r = await bench.request(
          '/projects/b2b-bench/missions/' + body.mission_id + '/agent-session',
          { scenario: body.scenario || 'alpha', method: 'POST' });
        return json(res, r.status, r.data); }
      if (url === '/_ctl/agent_proposal') {
        const r = await bench.request(
          '/projects/b2b-bench/missions/' + body.mission_id + '/agent-proposal',
          { scenario: body.scenario || 'alpha', method: 'POST' });
        return json(res, r.status, r.data); }
      if (url === '/_ctl/sign_proof') {
        const creds = bench.credentials[body.actor || 'alpha'];
        const reqFacade = { user: { _id: creds.user }, authStrategy: 'jwt',
          headers: { cookie: 'refreshToken=' + creds.refresh } };
        const attempt = await mongoose.connection.collection(PCOL)
          .findOne({ _id: body.attempt_id });
        const proof = await source.signReadProof(reqFacade, attempt);
        return json(res, 200, proof); }
      if (url === '/_ctl/journal') return json(res, 200, journal);
      if (url === '/_ctl/effects') return json(res, 200, bench.effects);
      if (url === '/_ctl/revoke') { await bench.revoke(body.scenario || 'alpha');
        return json(res, 200, { ok: true }); }
      if (url === '/_ctl/new_session') {
        const c = await bench.newSession(body.scenario || 'alpha');
        return json(res, 200, { session: c.session }); }
      if (url === '/_ctl/tickets') {
        const p = path.join(bench.allocationRoot, '.dubsar/tickets.json');
        const t = JSON.parse(await fs.promises.readFile(p, 'utf8'));
        if (body.tickets !== undefined)
          await fs.promises.writeFile(p, JSON.stringify(t.format ?
            { ...t, tickets: body.tickets } : { format: 'dubsar.tickets/1',
              tickets: body.tickets }));
        return json(res, 200, t); }
      return json(res, 404, { error: 'ctl' });
    } catch (e) { return json(res, 500, { error: String(e && e.message || e) }); }
  });
  await new Promise((r) => ctl.listen(0, '127.0.0.1', r));
  console.log(JSON.stringify({ ready: true,
    source_port: sourceComposition.port, ctl_port: ctl.address().port,
    origin: bench.origin,
    portal_public_key_pem: portal.publicKey,
    hermes_hub_private_pem: hermesHub.privateKey,
    hermes_ci_private_pem: hermesMemory.privateKey,
    actors: Object.keys(bench.credentials) }));
})().catch((e) => { console.log(JSON.stringify({ ready: false, error: String(e) })); });
"""


class P1Node:
    """Real P1 bench subprocess: native JWT + Mongo + pinned MyWork + real source
    listener. Ready JSON on stdout; test control on /_ctl."""

    def __init__(self, portal_root: str, mywork_root: str):
        self.portal_root = portal_root
        self.mywork_root = mywork_root
        self.proc = None
        self.info = None
        self.log = None

    def start(self, tmpdir, *, timeout: float = 90.0) -> "P1Node":
        script = os.path.join(str(tmpdir), "h1-bench.js")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(P1_BENCH_JS)
        self.log = open(os.path.join(str(tmpdir), "p1-node.log"), "w", encoding="utf-8")
        env = {"PATH": os.environ.get("PATH", ""), "SystemRoot": os.environ.get("SystemRoot", ""),
               "P1_PORTAL_ROOT": self.portal_root, "P1_MYWORK_ROOT": self.mywork_root}
        self.proc = subprocess.Popen(["node", script], cwd=self.portal_root, env=env,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True)
        line = self._readline_deadline(timeout)
        self.info = json.loads(line)
        assert self.info.get("ready"), f"P1 bench failed: {line}"
        return self

    def _readline_deadline(self, timeout: float) -> str:
        # stderr shares the pipe: stray Node/Mongo noise lines must not be
        # mistaken for the ready JSON -- skip them until the deadline.
        import queue as _q
        import threading as _t
        import time as _time
        q: _q.Queue = _q.Queue()
        def _drain():
            for line in self.proc.stdout:
                q.put(line)
        _t.Thread(target=_drain, daemon=True).start()
        deadline = _time.time() + timeout
        noise = []
        while _time.time() < deadline:
            try:
                line = q.get(timeout=max(0.05, deadline - _time.time())).strip()
            except _q.Empty:
                break
            try:
                json.loads(line)
                return line
            except ValueError:
                noise.append(line)
                if self.log:
                    self.log.write(line + "\n"); self.log.flush()
        raise RuntimeError(
            f"P1 bench emitted no ready JSON before deadline; noise={noise[:8]}")

    @property
    def source_url(self) -> str:
        return f"http://127.0.0.1:{self.info['source_port']}/internal/dubsar/b2b/source"

    def ctl(self, suffix: str, body: dict = None) -> dict:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.info['ctl_port']}{suffix}",
            data=json.dumps(body or {}).encode(), method="POST",
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")
            raise RuntimeError(f"ctl {suffix} -> {e.code}: {detail}") from e

    def sign_read_proof(self, *, actor="alpha", attempt_id: str) -> dict:
        """Genuine P1 signReadProof through the labelled control facade -- real
        PortalSessionLifecycle owner checks still run."""
        return self.ctl("/_ctl/sign_proof", {"actor": actor, "attempt_id": attempt_id})

    def set_bridge(self, *, port: int, hub_key: str, ci_key: str):
        return self.ctl("/_ctl/set_bridge",
                        {"port": port, "hub_key": hub_key, "ci_key": ci_key})

    def create_mission(self, *, scenario="alpha", body: dict = None) -> dict:
        payload = {"scenario": scenario,
                   "body": {"client_request_id": str(__import__('uuid').uuid4()),
                            **MISSION_FIXTURE, **(body or {})}}
        return self.ctl("/_ctl/mission", payload)

    def kill(self):
        if self.proc:
            self.proc.kill(); self.proc.wait()
        if self.log:
            self.log.close()


# ---------------------------------------------------------------------------
# Native Hermes child -- REAL APIServerAdapter.connect() (full route table +
# profile middleware), isolated root + profiles, scoped per-profile keys, no
# production hooks. Optional UNIT context producer + crash barriers are
# CHILD-ONLY wrappers; the child prints one ready JSON line.
# ---------------------------------------------------------------------------

HERMES_CHILD_PY = r"""
import asyncio, json, os, sys, time, faulthandler

# Native kill-switches BEFORE any native import — no implicit pip/bootstrap network.
os.environ['HERMES_DISABLE_LAZY_INSTALLS'] = '1'
os.environ['TIRITH_ENABLED'] = 'false'

os.environ['HERMES_HOME'] = os.environ['B2B_HOME']
os.environ.setdefault('TZ', 'UTC')
BARRIER_DIR = os.environ.get('B2B_BARRIER_DIR', '')
UNIT_MODE = os.environ.get('B2B_UNIT_MODE', '')
UNIT_TEMPLATE = os.environ.get('B2B_UNIT_TEMPLATE', '')
PROFILE = os.environ.get('B2B_DEFAULT_PROFILE', 'hub')

def _barrier(phase, before=True):
    # Write <phase>.reached then block while <phase>.release is absent.
    if not BARRIER_DIR:
        return
    marker = os.path.join(BARRIER_DIR, phase + ('.reached' if before else '.after'))
    release = os.path.join(BARRIER_DIR, phase + '.release')
    with open(marker, 'w') as fh:
        fh.write(json.dumps({'pid': os.getpid(), 'phase': phase}))
    while not os.path.exists(release):
        time.sleep(0.02)

def _install_barriers(store):
    # Child-local wrappers on the durable seams; never a production hook.
    if not BARRIER_DIR:
        return
    for name, phase in (('b2b_admit', 'admit'), ('b2b_commit_context', 'commit_context'),
                        ('b2b_cas_dispatch', 'cas_dispatch'),
                        ('b2b_commit_result', 'commit_result'),
                        ('b2b_seal', 'seal')):
        orig = getattr(store, name, None)
        if not callable(orig):
            continue
        def _wrap(orig=orig, phase=phase):
            def inner(*a, **k):
                _barrier(phase + '.before')
                out = orig(*a, **k)
                _barrier(phase + '.after', before=False)
                return out
            return inner
        setattr(store, name, _wrap())
    # provider-return-before-local-result: wrap the REAL OpenAI SDK create so the
    # response is fully parsed by the original, then the barrier hits before the
    # worker's result-commit -- a genuine dispatch receipt, not a pretend result.
    try:
        from openai.resources.chat.completions import Completions
        _orig_create = Completions.create
        def _b2b_create(self, *a, **k):
            out = _orig_create(self, *a, **k)
            _barrier('provider_return.before')
            return out
        Completions.create = _b2b_create
    except Exception:
        pass

def _unit_context_wrapper():
    # UNIT CONTEXT PRODUCER double: wraps the real hook seam, transforms the
    # frozen template, publishes receipt + registers recheck on the active cap.
    if not UNIT_MODE:
        return
    import agent.turn_context as tc
    _orig = tc._collect_pre_llm_call_context
    def _wrapped(agent, *a, **k):
        rendered = _orig(agent, *a, **k)
        if UNIT_MODE == 'middleware_exception':
            raise RuntimeError('UNIT middleware exception')
        from agent.b2b_execution import current_execution, register_context_recheck
        cap = current_execution(profile='', session_id=getattr(agent, 'session_id', '') or '')
        if cap is None:
            return rendered
        if UNIT_MODE == 'absent_render':
            return rendered  # producer declines to publish -- terminal must refuse
        import json as _j
        view = _j.loads(open(UNIT_TEMPLATE, encoding='utf-8').read())
        if UNIT_MODE == 'historical_render':
            pass  # template published unchanged; wrong-turn test rebinds turn_id
        turn_id = getattr(agent, '_current_turn_id', None) or 'turn-0'
        cap.publish_context(view, UNIT_RENDERED.encode('utf-8'), turn_id=turn_id)
        register_context_recheck(lambda _cap: {'source_basis': _cap.context_receipt.source_basis})
        return rendered + '\\n\\n' + UNIT_RENDERED if rendered else UNIT_RENDERED
    tc._collect_pre_llm_call_context = _wrapped

def _install_terminal_observer():
    # Test-only observer on the REAL execute_terminal/require_execution -- proves
    # the actual AIAgent reached the B2B terminal seam and classifies the refusal.
    # Append-only fsync trace; never a mock or decision replacement.
    try:
        import agent.b2b_execution as _be
        _orig = _be.execute_terminal
        _orig_require = _be.require_execution
        trace_path = os.environ.get('B2B_TRACE_FILE', '')
        import json as _j
        def _write(entry):
            if not trace_path:
                return
            with open(trace_path, 'a', encoding='utf-8') as fh:
                fh.write(_j.dumps(entry) + '\n'); fh.flush(); os.fsync(fh.fileno())
        def _traced(*a, **k):
            agent = k.get('agent') or (a[0] if a else None)
            cap = k.get('cap') or (a[2] if len(a) >= 3 else None)
            _write({'type': 'terminal_entry',
                    'agent_type': (type(agent).__module__ + '.' + type(agent).__qualname__)
                                  if agent is not None else '',
                    'session_id': getattr(cap, 'session_id', ''),
                    'attempt_id': getattr(cap, 'attempt_id', ''),
                    'run_id': getattr(cap, 'run_id', '')})
            try:
                return _orig(*a, **k)
            except _be.B2BTerminalRefusal as exc:
                _write({'type': 'terminal_refused', 'code': str(exc)})
                raise
        def _traced_require(*a, **k):
            try:
                return _orig_require(*a, **k)
            except _be.B2BTerminalRefusal as exc:
                _write({'type': 'require_refused', 'code': str(exc)})
                raise
        _be.execute_terminal = _traced
        _be.require_execution = _traced_require
        # Phase-level tracer: records ANY exception escaping a turn phase so a
        # refusal swallowed by the generic api-error path stays attributable.
        import agent.conversation_loop as _cl
        _orig_phase = _cl._run_phase
        def _traced_phase(fn, agent, s, **kw):
            try:
                return _orig_phase(fn, agent, s, **kw)
            except BaseException as exc:
                _write({'type': 'phase_raised',
                        'phase': getattr(fn, '__name__', repr(fn)),
                        'exc_type': type(exc).__module__ + '.' + type(exc).__qualname__,
                        'exc': str(exc)})
                raise
        _cl._run_phase = _traced_phase
        # Context-length resolution tracer: records callers that reach the live
        # probe path (config_context_length falsy) so a stray probe is attributable.
        try:
            import agent.model_metadata as _mm
            _orig_gmcl = _mm.get_model_context_length
            def _traced_gmcl(model, base_url='', api_key='', config_context_length=None,
                             provider='', custom_providers=None):
                import traceback as _tb
                if not config_context_length:
                    _write({'type': 'gmcl_probe_path',
                            'model': str(model), 'provider': str(provider),
                            'caller': _tb.extract_stack(limit=6)[-2].name})
                return _orig_gmcl(model, base_url=base_url, api_key=api_key,
                                  config_context_length=config_context_length,
                                  provider=provider, custom_providers=custom_providers)
            _mm.get_model_context_length = _traced_gmcl
        except Exception:
            pass
        # HTTP caller attribution: journal every httpx POST with its caller frame
        # so an un-pinned metadata probe can be traced to the exact call site.
        try:
            import httpx as _hx, traceback as _tb2
            for _cls in (_hx.Client, _hx.AsyncClient):
                _orig_post = _cls.post
                def _mk(orig):
                    def _traced_post(self, url, *a, **k):
                        try:
                            _write({'type': 'httpx_post', 'url': str(url),
                                    'caller': _tb2.extract_stack(limit=8)[-2].name})
                        except Exception:
                            pass
                        return orig(self, url, *a, **k)
                    return _traced_post
                _cls.post = _mk(_orig_post)
        except Exception:
            pass
        _write({'type': 'observer_installed'})
    except Exception as _e:
        raise RuntimeError(f'terminal observer install failed: {_e}')


def _install_egress_fence():
    # Child-only outbound quarantine: allow ONLY loopback + explicit
    # test source/provider/native ports; journal every denial. No production
    # config -- test control fields only.
    if not os.environ.get('B2B_EGRESS_FENCE'):
        return
    import socket as _s, json as _j
    allowed = {int(p) for p in os.environ.get('B2B_ALLOWED_PORTS', '').split(',') if p}
    ledger = os.environ.get('B2B_EGRESS_LEDGER', '')
    _orig_connect = _s.socket.connect
    _orig_connect_ex = _s.socket.connect_ex
    _orig_getaddrinfo = _s.getaddrinfo
    def _log(host, port):
        if ledger:
            with open(ledger, 'a', encoding='utf-8') as fh:
                fh.write(_j.dumps({'denied': f'{host}:{port}'}) + '\n')
                fh.flush(); os.fsync(fh.fileno())
    def _allow(host, port):
        return host in ('127.0.0.1', 'localhost', '::1') and int(port) in allowed
    def _guarded_connect(self, address):
        host, port = address[0], int(address[1])
        if _allow(host, port):
            return _orig_connect(self, address)
        _log(host, port)
        raise OSError(f'egress denied: {host}:{port}')
    def _guarded_connect_ex(self, address):
        host, port = address[0], int(address[1])
        if _allow(host, port):
            return _orig_connect_ex(self, address)
        _log(host, port)
        return errno_ECONNREFUSED
    import errno as _errno; errno_ECONNREFUSED = _errno.ECONNREFUSED
    def _guarded_getaddrinfo(host, port, *a, **k):
        if host not in ('127.0.0.1', 'localhost', '::1', None):
            _log(str(host), port)
            raise OSError(f'dns denied: {host}:{port}')
        return _orig_getaddrinfo(host, port, *a, **k)
    _s.socket.connect = _guarded_connect
    _s.socket.connect_ex = _guarded_connect_ex
    _s.getaddrinfo = _guarded_getaddrinfo
    # Proactor + selector async paths: patch the CLASS methods so every loop —
    # main AND the workers' own asyncio.run loops — enforces the allowlist.
    for _cls_name in (
            'asyncio.proactor_events.BaseProactorEventLoop',
            'asyncio.selector_events.BaseSelectorEventLoop'):
        try:
            _mod, _name = _cls_name.rsplit('.', 1)
            _cls = getattr(__import__(_mod, fromlist=[_name]), _name)
            _orig_sock = _cls.sock_connect
            async def _guarded_sock(self, sock, address, _orig=_orig_sock):
                host, port = address[0], int(address[1])
                if _allow(host, port):
                    return await _orig(self, sock, address)
                _log(host, port)
                raise OSError(f'egress denied: {host}:{port}')
            _cls.sock_connect = _guarded_sock
        except Exception as _e:
            if os.environ.get('B2B_EGRESS_LEDGER'):
                _log('guard_install_failed', str(_e))


def _bootstrap_profile(home, name, api_key):
    import os as _o
    pdir = _o.path.join(home, 'profiles', name)
    _o.makedirs(pdir, exist_ok=True)
    with open(_o.path.join(pdir, '.env'), 'w') as fh:
        fh.write(f'API_SERVER_KEY={api_key}\n'
                 f'OPENAI_API_KEY=sk-unit-{name}-' + _o.urandom(4).hex() + '\n')
    with open(_o.path.join(pdir, 'config.yaml'), 'w') as fh:
        fh.write('model:\n  default: unit-double\n  provider: custom\n'
                 '  base_url: "' + os.environ['B2B_PROVIDER_URL'] + '"\n'
                 '  api_mode: chat_completions\n  context_length: 256000\n'
                 '  ollama_num_ctx: 256000\n  supports_vision: false\n'
                 # Bounded lanes force compression off post-init; declaring it keeps
                 # the init-time aux feasibility probe (Ollama /api/show) silent too.
                 'compression:\n  enabled: false\n'
                 # The ollama_num_ctx pin marks the double as Ollama, which arms the
                 # reasoning gate's /api/show thinking probe -- declare the test
                 # model non-reasoning so the gate returns before any live probe.
                 'model_overrides:\n  custom:\n    unit-double:\n'
                 '      supports_reasoning: false\n')
    return pdir

async def _main():
    from agent.secret_scope import set_multiplex_active
    set_multiplex_active(True)
    home = os.environ['B2B_HOME']
    keys = json.loads(os.environ['B2B_PROFILE_KEYS'])
    for name, key in keys.items():
        _bootstrap_profile(home, name, key)
    # Default-profile startup guard needs a real API_SERVER_KEY -- random per child,
    # in process env so the pre-connect guard sees it (not a real secret).
    _key = os.urandom(16).hex()
    os.environ['API_SERVER_KEY'] = _key
    with open(os.path.join(home, '.env'), 'w') as fh:
        fh.write('API_SERVER_KEY=' + _key + '\n')
    _unit_context_wrapper()
    _install_terminal_observer()
    _install_egress_fence()
    from gateway.config import PlatformConfig
    from gateway.platforms.api_server import APIServerAdapter
    extra = {'b2b': json.loads(os.environ['B2B_CONFIG']),
             'multiplex_profiles': True}
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra=extra))
    adapter._port = int(os.environ.get('B2B_PORT', '0'))
    import types as _t
    # Minimal native gateway_runner: config.multiplex_profiles=True is the REAL
    # switch the prefix middleware + profiles_to_serve read -- no resolver mock.
    adapter.gateway_runner = _t.SimpleNamespace(
        config=_t.SimpleNamespace(multiplex_profiles=True))
    _install_barriers(getattr(adapter, '_run_idempotency_store', None))
    ok = await adapter.connect()
    if not ok or adapter._site is None:
        raise RuntimeError('native adapter connect() did not bind')
    port = adapter._site._server.sockets[0].getsockname()[1]
    ready = os.environ.get('B2B_READY_FILE', '')
    payload = json.dumps({'ready': True, 'port': port, 'pid': os.getpid()})
    if ready:
        with open(ready, 'w', encoding='utf-8') as fh:
            fh.write(payload)
    print(payload, flush=True)
    _stack = os.environ.get('B2B_STACK_FILE', '')
    _stack_fh = open(_stack, 'a', encoding='utf-8') if _stack else None
    if _stack_fh is not None:
        # One-shot delayed dump: forensic detail for a wedged run without a
        # repeating all-threads frame walk (repeat=True raced thread create/
        # teardown and segfaulted the child under load).
        faulthandler.dump_traceback_later(45, repeat=False, file=_stack_fh)
    await asyncio.Event().wait()

asyncio.run(_main())
"""


class HermesChild:
    """Real native adapter subprocess. Sanitized env (OS essentials + explicit
    test vars only -- no inherited provider/telemetry credentials)."""

    def __init__(self, *, python: str, repo_root: str):
        self.python = python
        self.repo_root = repo_root
        self.proc = None
        self.port = None
        self.pid = None
        self.stdout = None
        self.stderr = None

    def start(self, tmpdir, *, home: str, b2b_config: dict, profile_keys: dict,
              provider_url: str, barriers: bool = False, unit_mode: str = "",
              unit_template: str = "", allowed_ports: str = "",
              timeout: float = 90.0) -> "HermesChild":
        self.tmpdir = str(tmpdir)
        self.trace_path = os.path.join(self.tmpdir, "terminal-trace.jsonl")
        self.denial_path = os.path.join(self.tmpdir, "egress-denied.jsonl")
        os.makedirs(str(tmpdir), exist_ok=True)
        os.makedirs(home, exist_ok=True)
        script = os.path.join(str(tmpdir), "h1-child.py")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(HERMES_CHILD_PY)
        self.stdout = open(os.path.join(str(tmpdir), "hermes-stdout.log"), "w")
        self.stderr = open(os.path.join(str(tmpdir), "hermes-stderr.log"), "w")
        barrier_dir = os.path.join(str(tmpdir), "barriers")
        if barriers:
            os.makedirs(barrier_dir, exist_ok=True)
        env = {
            "PATH": os.environ.get("PATH", ""),
            "SystemRoot": os.environ.get("SystemRoot", ""),
            "USERPROFILE": os.environ.get("USERPROFILE", ""),
            "LOCALAPPDATA": os.environ.get("LOCALAPPDATA", ""),
            "APPDATA": os.environ.get("APPDATA", ""),
            "HOME": os.environ.get("HOME", ""),
            "PYTHONPATH": self.repo_root, "B2B_HOME": home,
            "B2B_CONFIG": json.dumps(b2b_config),
            "B2B_PROFILE_KEYS": json.dumps(profile_keys),
            "B2B_PROVIDER_URL": provider_url,
            "B2B_BARRIER_DIR": barrier_dir if barriers else "",
            "B2B_UNIT_MODE": unit_mode, "B2B_UNIT_TEMPLATE": unit_template,
            "B2B_PORT": "0",
            "B2B_TRACE_FILE": os.path.join(str(tmpdir), "terminal-trace.jsonl"),
            "B2B_EGRESS_FENCE": "1",
            "B2B_ALLOWED_PORTS": allowed_ports or "",
            "B2B_EGRESS_LEDGER": os.path.join(str(tmpdir), "egress-denied.jsonl"),
            "B2B_STACK_FILE": os.path.join(str(tmpdir), "thread-stack.log"),
        }
        ready_path = os.path.join(str(tmpdir), "hermes-ready.json")
        env["B2B_READY_FILE"] = ready_path
        self.proc = subprocess.Popen(
            [self.python, script], cwd=self.repo_root, env=env,
            stdout=self.stdout, stderr=self.stderr, text=True)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"Hermes child died during boot (rc={self.proc.returncode}); "
                    f"see {self.stderr.name}")
            if os.path.exists(ready_path):
                info = json.loads(open(ready_path).read())
                assert info.get("ready"), info
                self.port, self.pid = info["port"], info["pid"]
                return self
            time.sleep(0.2)
        raise TimeoutError(f"Hermes child did not signal ready in {timeout}s")

    async def async_request(self, method: str, path: str, **kwargs):
        """Async wrapper -- never blocks the caller's event loop (keeps the
        loopback provider double live during positive UNIT tests)."""
        return await asyncio.to_thread(self.request, method, path, **kwargs)

    def request(self, method: str, path: str, *, profile: str = "hub", key: str = "",
                body: dict = None, headers: dict = None, timeout: float = 15.0):
        url = f"http://127.0.0.1:{self.port}/p/{profile}{path}"
        h = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        h.update(headers or {})
        req = urllib.request.Request(
            url, data=json.dumps(body).encode() if body is not None else None,
            method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"null")
            except Exception:
                return e.code, {"raw": e.read().decode("utf-8", "replace")}

    def kill(self) -> Optional[int]:
        """Physical termination; returns the real exit code."""
        if not self.proc:
            return None
        self.proc.kill()
        self.proc.wait()
        return self.proc.returncode

    def close_logs(self):
        for fh in (self.stdout, self.stderr):
            if fh:
                fh.close()


class ProviderDouble:
    """Loopback provider double -- canned chat.completion, durable fsync'd journal
    of every request (path, X-Dubsar-* headers, body). Wired through scoped .env
    so provider resolution SUCCEEDS and the turn reaches the terminal."""

    def __init__(self):
        self.runner = None
        self.port = None
        self.journal_path = None

    async def start(self, tmpdir):
        from aiohttp import web
        self.journal_path = os.path.join(str(tmpdir), "provider-journal.jsonl")
        # Journal exists fsync'd at startup -- proves availability before any request.
        with open(self.journal_path, "w") as fh:
            fh.flush(); os.fsync(fh.fileno())

        @web.middleware
        async def journal_every_request(request, handler):
            """Observe ALL inbound -- any route/method, including 404s and aux
            calls -- so 'zero provider HTTP' is proven, not assumed."""
            auth = request.headers.get("Authorization", "")
            entry = {
                "method": request.method, "path": request.path,
                "auth_sha256": hashlib.sha256(auth.encode()).hexdigest() if auth else None,
                "attempt_id": request.headers.get("X-Dubsar-Attempt-Id"),
                "request_digest": request.headers.get("X-Dubsar-Request-Digest"),
            }
            with open(self.journal_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n"); fh.flush(); os.fsync(fh.fileno())
            return await handler(request)

        async def chat(request):
            return web.json_response({
                "id": "cmpl-unit-double", "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant",
                    "content": json.dumps(PROVIDER_FIXTURE)},
                    "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

        app = web.Application(middlewares=[journal_every_request])
        app.router.add_post("/v1/chat/completions", chat)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]
        return self

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"

    def journal(self) -> list:
        if not self.journal_path or not os.path.exists(self.journal_path):
            return []
        return [json.loads(line) for line in
                open(self.journal_path, encoding="utf-8") if line.strip()]

    async def stop(self):
        if self.runner:
            await self.runner.cleanup()


def b2b_child_config(*, source_url: str, portal_pub_pem: str,
                     hermes_priv_pems: dict, provider_url: str,
                     contract_root: str) -> dict:
    """Operator b2b config for the child -- one entry per served profile, own
    Hermes issuer/keypair each (never the Portal private)."""
    profiles = {}
    for profile, priv in hermes_priv_pems.items():
        profiles[profile] = {
            "source_url": source_url,
            "portal_issuer": "portal-h1",
            "hermes_issuer": f"hermes-h1-{profile}",
            "portal_public_key_pem": portal_pub_pem,
            "hermes_private_key_pem": priv,
            "projects": {"b2b-bench": {
                "project_id": "b2b-bench", "bot_id": "bot",
                "profile_id": profile, "allowed_namespaces": ["ns"],
                "context_contract_root": contract_root,
                "model": "unit-double", "provider": "custom",
                "base_url": provider_url, "api_mode": "chat_completions",
                "logical_mission": None, "project_context": None}}}
    return {"enabled": True, "profiles": profiles}


