# Mivia evidence pack, version 1

A pack is a zip file. Paths are relative to its root.

| Path | Content | Fixed at registration? |
|---|---|---|
| `1-registration/manifest.json` | The registration record: canonical JSON bytes, exactly as signed | Yes |
| `1-registration/manifest.sig` | Raw 64-byte Ed25519 signature over `manifest.json` by the platform key | Yes |
| `1-registration/timestamp.ots` | OpenTimestamps proof for BLAKE3(`manifest.json`) | Yes (upgraded once anchored) |
| `1-registration/bitcoin.json` | `{"block": <height>, "txid": "<hex>"}`, once anchored | Yes |
| `1-registration/watermark-payload.hex` | The 20-byte watermark payload, hex (web registrations) | Yes |
| `1-registration/fingerprint.chromaprint` | Registered Chromaprint fingerprint: uint32 little-endian array | Yes |
| `2-statement/statement.json` | Mivia's statement: canonical JSON | No: dated |
| `2-statement/statement.sig` | Raw 64-byte Ed25519 signature over `statement.json` by the statement key | No |
| `3-keys/mivia-keys.json` | Both public keys | |
| `README.txt`, `summary.html` | Human-readable | |

Files that do not apply to a record are absent.

## Canonical JSON

Used for `manifest.json` and `statement.json`: UTF-8; object keys sorted by code point at every level; no whitespace outside strings; separators `,` and `:`; non-ASCII characters written as themselves, not escaped; no floating-point numbers. The signature covers these exact bytes, so a verifier must hash and check the file as it is, never a re-serialisation.

## The registration record

```
{
  "created_utc": "<ISO 8601 UTC>",
  "creator": "<account display name>",
  "extensions": {
    "audio":    { "file_sha256": "<SHA-256 of the uploaded file, hex>" },
    "creation": { ... DAW project history position ... },
    "parents":  [ ... declared lineage ... ]
  },
  "licence": "...", "splits": [], "title": "...", "work_id": "..."
}
```

`extensions` and each of its members are optional. `audio` exists for records registered from October 2026.

- **Record hash:** BLAKE3-256 of `manifest.json`.
- **Record id:** the first 8 bytes of the record hash, hex. The certificate lives at `https://mivia.co/c/<id>`.

## Timestamp

`timestamp.ots` is a standard OpenTimestamps file whose file digest is the record's **BLAKE3** hash. Its header names SHA-256 as the file hash operation, so check it against the digest directly, not against a file: `ots verify -d <record hash hex> timestamp.ots`. A Bitcoin attestation's digest is the block's merkle root, which block explorers display byte-reversed.

## Watermark payload (20 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | magic `0xFB` |
| 1 | 1 | payload version |
| 2 | 4 | issuer id: first 4 bytes of BLAKE3(platform public key) |
| 6 | 8 | first 8 bytes of the record hash |
| 14 | 4 | nonce |
| 18 | 2 | CRC-16/CCITT-FALSE of bytes 0 to 17, big-endian |

## Statement

Canonical JSON with at least: `type` (`"mivia-evidence-statement"`), `version` (1), `generated_utc`, `record` (`id`, `manifest_blake3`, `certificate_url`, `registered_utc`, `status`, `status_reason`, `status_changed_utc`), `assurance`, `creation`, `lineage`, `timestamp`, `scans` (date and match method only), `statement_key_b64`, and `files`: every file in the pack outside `2-statement/`, sorted by path, each with its SHA-256 hex.

## Keys

`3-keys/mivia-keys.json`:

```
{ "keys": {
    "platform":  { "algorithm": "Ed25519", "public_key_b64": "...", "public_key_hex": "..." },
    "statement": { "algorithm": "Ed25519", "public_key_b64": "...", "public_key_hex": "..." } } }
```

Compare them with `https://mivia.co/.well-known/mivia-keys.json` and with `src/mivia_verify/keys.py` in this repository. The platform key signs registrations only; the statement key signs pack statements only.

## Fingerprint comparison

`fpcalc -length 120 -raw -json <file>`, values taken as uint32. Score: the lowest bit-error rate over every alignment of the two arrays with at least 80 overlapping values. Mivia treats a score below 0.35 as a match.
