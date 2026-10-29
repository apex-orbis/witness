#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Apex Orbis Ltd
"""Verify anything published in apex-orbis/witness. Standard library only.

  python verify.py chain  <ledger>/MANIFEST.jsonl   check every entry hash and the prev_hash chain
  python verify.py proof  PROOF.json [MANIFEST]     check a revealed record against its sealed batch
                                                    (and, if MANIFEST is given, that the batch is in it)

Hashing (identical to the private sealing tool):
  canonical JSON  = RFC 8785 (JCS)
  entry_hash      = SHA-256(JCS(entry without entry_hash)); genesis prev_hash = 64 zeros
  leaf            = SHA-256(0x00 || JCS(record))          (record includes its random salt)
  node            = SHA-256(0x01 || left || right)        (odd node is paired with itself)

Dates: a manifest's `sealed_at` is self-reported. The independent dates are the
GitHub pull request that added the line (server-recorded `created_at`) and the
OpenTimestamps file in <ledger>/ots/ (verify at https://opentimestamps.org).
"""
from __future__ import annotations

import hashlib
import json
import math
import sys

GENESIS = "0" * 64


def _num(x) -> str:
    if isinstance(x, bool):
        raise TypeError("bool is not a number")
    if isinstance(x, int):
        return str(x)
    if not math.isfinite(x):
        raise ValueError("JCS forbids NaN and Infinity")
    if x == int(x) and abs(x) < 1e21:
        return str(int(x))
    r = repr(x)
    if "e" in r or "E" in r:
        raise ValueError(f"exponent notation not supported: {r}")
    return r


def jcs(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return _num(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k]) for k in keys) + "}"
    raise TypeError(type(v).__name__)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def entry_hash(e: dict) -> str:
    return sha(jcs({k: x for k, x in e.items() if k != "entry_hash"}).encode("utf-8"))


def leaf(record: dict) -> str:
    return sha(b"\x00" + jcs(record).encode("utf-8"))


def node(a: str, b: str) -> str:
    return sha(b"\x01" + bytes.fromhex(a) + bytes.fromhex(b))


def read_manifest(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def chain(path: str) -> bool:
    prev, ok = GENESIS, True
    entries = read_manifest(path)
    for i, e in enumerate(entries, start=1):
        bad = [m for m, cond in (("seq", e.get("seq") != i), ("prev_hash", e.get("prev_hash") != prev),
                                 ("entry_hash", entry_hash(e) != e.get("entry_hash"))) if cond]
        print(f"#{i} {e.get('entry_hash', '')[:16]}  {'OK' if not bad else 'BAD ' + ', '.join(bad)}")
        ok &= not bad
        prev = e.get("entry_hash")
    print(f"{len(entries)} entries, head {prev}: {'VALID' if ok else 'INVALID'}")
    return ok


def proof(path: str, manifest: str | None) -> bool:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    e = doc["manifest_entry"]
    ok = entry_hash(e) == e["entry_hash"]
    for p in doc["proofs"]:
        h = leaf(p["record"])
        for step in p["path"]:
            h = node(h, step["hash"]) if step["side"] == "R" else node(step["hash"], h)
        ok &= h == e["merkle_root"]
    if manifest:
        ok &= any(m.get("entry_hash") == e["entry_hash"] for m in read_manifest(manifest))
    print(f"{'VALID' if ok else 'INVALID'}: batch seq {e['seq']} ({e['batch']}), entry_hash {e['entry_hash']}")
    return ok


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) >= 2 and a[0] == "chain":
        sys.exit(0 if chain(a[1]) else 1)
    if len(a) >= 2 and a[0] == "proof":
        sys.exit(0 if proof(a[1], a[2] if len(a) > 2 else None) else 1)
    raise SystemExit(__doc__)
