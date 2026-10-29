# witness

**Public timestamps for Apex Orbis records.** This repository holds hashes only. Contents stay private until Apex Orbis chooses to reveal them.

It exists so that anyone can check, without trusting us, that a record existed **unchanged** at a given time. Typical uses are a forecast made before its outcome, or a decision recorded before it was acted on.

## Layout

One folder per ledger. Each folder has its own hash chain, and ledgers never mix.

| Folder | Ledger | Since |
|---|---|---|
| [`kepler/`](kepler/) | Kepler: calibrated forecasts on AI-industry news items, scored later against what actually happened | 2026-10-29 |

Each folder contains:

- **`MANIFEST.jsonl`:** one line per sealed batch. Each line holds `seq`, `kind` (`live` or `backtest`), `n_records`, the batch's `file_sha256` and `merkle_root`, `sealed_at`, `prev_hash` and `entry_hash`. Every line commits to the one before it, so the latest `entry_hash` commits to the whole history.
- **`ots/`:** [OpenTimestamps](https://opentimestamps.org) proofs anchoring manifest prefixes into Bitcoin.

`backtest` batches hold ratings made after the fact on older items. They are published for completeness and **never count toward a track record**.

## What the dates mean

- `sealed_at` is written by us. Treat it as a claim.
- **The pull request that added a line** carries a `created_at` recorded by GitHub's servers. It can't be backdated.
- **The `.ots` file** proves the manifest existed before a specific Bitcoin block. Drop the manifest prefix (`MANIFEST-NNNN.jsonl` is the first NNNN lines of `MANIFEST.jsonl`) and its `.ots` file on https://opentimestamps.org.

## Verifying a revealed record

When Apex Orbis reveals a record, it shares a `proof.json` containing the record (with its random salt), the Merkle path, and the manifest entry. Then:

```bash
python verify.py chain kepler/MANIFEST.jsonl                 # the chain is intact
python verify.py proof proof.json kepler/MANIFEST.jsonl      # the record was in that sealed batch
```

`verify.py` uses only the Python standard library. Its hashing rules are listed at the top of the file:
- RFC 8785 canonical JSON;
- SHA-256;
- domain-separated Merkle leaves and nodes.

The salts mean that unrevealed records cannot be guessed from the hashes.

## Rules

- **Append-only.** Lines are never edited, reordered or removed. A correction is a new record that names what it supersedes.
- **Additions arrive as pull requests**, so each one gets an independent server timestamp.

`verify.py` is Apache-2.0. The hashes and timestamps are facts, and no rights are claimed in them.
