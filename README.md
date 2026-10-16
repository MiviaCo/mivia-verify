# mivia-verify

Check a [Mivia](https://mivia.co) evidence pack yourself, without relying on Mivia.

Every recording registered with Mivia has a public Certificate of Registration. Its owner can download an **evidence pack**: a zip with the signed registration record, its Bitcoin timestamp and Mivia's signed, dated statement about the record. This tool checks every part of a pack and tells you, in plain language, what passed.

**What a pack proves:** what was registered, by which Mivia account, and that the record existed no later than a given Bitcoin block. **What it does not prove:** who wrote the music or who owns it. That is for contracts, registries and courts.

## Install

Python 3.9 or later:

```
pip install git+https://github.com/MiviaCo/mivia-verify
```

To compare an audio file by its acoustic fingerprint, also install Chromaprint's `fpcalc` (`brew install chromaprint`, `apt install libchromaprint-tools`, or <https://acoustid.org/chromaprint>).

## Use

```
mivia-verify mivia-evidence-<id>-<date>.zip
mivia-verify mivia-evidence-<id>-<date>.zip --audio the-recording.wav
```

| Option | What it does |
|---|---|
| `--audio FILE` | Check whether FILE is the exact registered file, and whether it matches the registered recording by fingerprint |
| `--offline` | No network at all: skips comparing keys with mivia.co and looking up the Bitcoin block |
| `--bitcoin-node` | Look the block up with your own Bitcoin node (`bitcoin-cli`) instead of a public block explorer |
| `--json` | Machine-readable output |

The exit code is 0 when every check that could run passed, and 1 otherwise.

## What it checks

1. **The record is intact.** BLAKE3 of `1-registration/manifest.json` gives the record id, the same id as in the certificate address `mivia.co/c/<id>`.
2. **Signed by Mivia.** The Ed25519 signature in `manifest.sig` is valid for the record.
3. **The keys are Mivia's.** The keys in the pack match the copy pinned in this repository (`src/mivia_verify/keys.py`) and the copy published at <https://mivia.co/.well-known/mivia-keys.json>.
4. **The Bitcoin timestamp.** The OpenTimestamps proof starts from the record's BLAKE3 hash and leads to the merkle root of a Bitcoin block, confirmed with a public block explorer or your own node. Nobody, including Mivia, can backdate it.
5. **The watermark payload** (web registrations) points to this record and to Mivia's key. Reading the payload from audio needs Mivia's decoder or the public scan on mivia.co; this tool checks that the payload in the pack belongs to the record.
6. **Mivia's dated statement** is signed by Mivia's statement key and lists every other file in the pack with its SHA-256, so nothing can be added, removed or changed. It is Mivia's account on the date shown (assurance level, warnings, creation history, lineage, scan dates); a later pack may say more.
7. **The audio** (with `--audio`):
   - **exact file:** for records registered from October 2026, the record contains the SHA-256 of the file that was uploaded; a creator who kept that file can prove it is the one;
   - **fingerprint:** compared with the registered Chromaprint fingerprint. A similarity measure: it also matches re-encoded or edited copies.

A check that could not run (offline, no proof yet, no fingerprint) is shown as `----`, not as a failure.

You do not have to trust this tool either: [SPEC.md](SPEC.md) describes the pack precisely enough to write your own checker.

## Licence

Apache-2.0. This repository contains the pack format and the checks only; Mivia's watermarking engine is not part of it.
