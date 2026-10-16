"""The checks. Same rules as the web checker on mivia.co; see SPEC.md."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import shutil
import subprocess
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

import blake3
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from . import ots

# Fingerprint matching, as on mivia.co (functions/_lib/chromaprint.ts).
FP_MATCH_THRESHOLD = 0.35
FP_MIN_OVERLAP_FRAMES = 80


@dataclass
class Check:
    id: str
    ok: Optional[bool]  # True pass, False fail, None could not be checked
    title: str
    detail: str


@dataclass
class Keys:
    platform: bytes
    statement: bytes


@dataclass
class Verdict:
    checks: List[Check] = field(default_factory=list)
    record_id: Optional[str] = None
    manifest: Dict = field(default_factory=dict)
    statement: Optional[Dict] = None

    @property
    def failed(self) -> bool:
        return any(c.ok is False for c in self.checks)


BlockLookup = Callable[[int], Optional[Tuple[str, int]]]  # height -> (merkle root hex as explorers show it, unix time)


def _verify_sig(sig: Optional[bytes], msg: bytes, pub: Optional[bytes]) -> bool:
    if not sig or not pub:
        return False
    try:
        VerifyKey(pub).verify(msg, sig)
        return True
    except (BadSignatureError, ValueError):
        return False


def _crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def _day(unix: int) -> str:
    return datetime.fromtimestamp(unix, tz=timezone.utc).strftime("%-d %B %Y")


def _u32s(raw: bytes) -> List[int]:
    return [int.from_bytes(raw[i : i + 4], "little") for i in range(0, len(raw) - len(raw) % 4, 4)]


def alignment_score(a: List[int], b: List[int]) -> float:
    """Lowest bit-error rate over all alignments with at least 80 overlapping frames."""
    best = 1.0
    la, lb, m = len(a), len(b), FP_MIN_OVERLAP_FRAMES
    for offset in range(-(lb - m), la - m + 1):
        if offset >= 0:
            ao, bo, n = offset, 0, min(la - offset, lb)
        else:
            ao, bo, n = 0, -offset, min(lb + offset, la)
        diff = sum(bin(a[ao + i] ^ b[bo + i]).count("1") for i in range(n))
        best = min(best, diff / (n * 32))
    return best


def fpcalc_fingerprint(path: str) -> Optional[List[int]]:
    """Chromaprint of an audio file, computed the way Mivia computes it at registration."""
    exe = shutil.which("fpcalc")
    if not exe:
        return None
    out = subprocess.run(
        [exe, "-length", "120", "-raw", "-json", path], capture_output=True, check=False
    )
    if out.returncode != 0:
        return None
    return [v & 0xFFFFFFFF for v in json.loads(out.stdout)["fingerprint"]]


def verify_pack(
    pack: bytes,
    audio_path: Optional[str] = None,
    published: Optional[Keys] = None,
    pinned: Optional[Keys] = None,
    block_lookup: Optional[BlockLookup] = None,
) -> Verdict:
    v = Verdict()
    try:
        with zipfile.ZipFile(io.BytesIO(pack)) as z:
            files = {n: z.read(n) for n in z.namelist() if not n.endswith("/")}
    except zipfile.BadZipFile:
        v.checks.append(Check("record", False, "Not an evidence pack", "The file is not a readable zip."))
        return v
    manifest = files.get("1-registration/manifest.json")
    if manifest is None:
        v.checks.append(Check("record", False, "Not an evidence pack", "There is no 1-registration/manifest.json."))
        return v

    pack_keys: Optional[Keys] = None
    try:
        k = json.loads(files["3-keys/mivia-keys.json"])["keys"]
        pack_keys = Keys(
            base64.b64decode(k["platform"]["public_key_b64"]),
            base64.b64decode(k["statement"]["public_key_b64"]),
        )
    except (KeyError, ValueError, TypeError):
        pack_keys = None

    # 1. Record integrity.
    h = blake3.blake3(manifest).digest()
    rid = h[:8].hex()
    v.record_id = rid
    try:
        v.manifest = json.loads(manifest)
    except ValueError:
        v.manifest = {}
    try:
        v.statement = json.loads(files["2-statement/statement.json"])
    except (KeyError, ValueError):
        v.statement = None
    rec = (v.statement or {}).get("record", {})
    rec_ok = not rec.get("id") or (rec.get("id") == rid and rec.get("manifest_blake3") == h.hex())
    v.checks.append(
        Check(
            "record",
            rec_ok,
            "The record is intact" if rec_ok else "The record does not match its id",
            f"BLAKE3 of the record gives the id {rid}. Make sure this is the id in the certificate "
            f"address you were given (mivia.co/c/{rid})."
            if rec_ok
            else f"The record's content gives the id {rid}, but the pack says {rec.get('id')}. "
            "The record has been changed.",
        )
    )

    # 2. Mivia's signature over the record.
    sig_ok = _verify_sig(files.get("1-registration/manifest.sig"), manifest, pack_keys and pack_keys.platform)
    v.checks.append(
        Check(
            "signature",
            sig_ok,
            "Signed by Mivia" if sig_ok else "The signature does not match",
            "Mivia's Ed25519 signature on the record is valid, so it has not been changed since it was registered."
            if sig_ok
            else "The record was changed after signing, or was not signed by the key in this pack.",
        )
    )

    # 3. The keys are Mivia's: compared with the copy pinned in this tool and the one on mivia.co.
    if pack_keys is None:
        v.checks.append(Check("keys", False, "Keys missing", "The pack has no readable 3-keys/mivia-keys.json."))
    else:
        refs = [(n, k) for n, k in (("this tool", pinned), ("mivia.co", published)) if k is not None]
        if not refs:
            v.checks.append(
                Check("keys", None, "Keys not compared", "No reference copy of Mivia's keys was available.")
            )
        else:
            bad = [n for n, k in refs if (k.platform, k.statement) != (pack_keys.platform, pack_keys.statement)]
            names = " and ".join(n for n, _ in refs)
            v.checks.append(
                Check(
                    "keys",
                    not bad,
                    "The keys are Mivia's published keys" if not bad else "The keys are not Mivia's",
                    f"The keys in the pack match the copy held by {names}."
                    if not bad
                    else f"The keys in the pack differ from the copy held by {' and '.join(bad)}. Do not rely on it.",
                )
            )

    # 4. Bitcoin timestamp for BLAKE3(manifest.json).
    ots_file = files.get("1-registration/timestamp.ots")
    if ots_file is None:
        v.checks.append(Check("timestamp", None, "No timestamp yet", "The pack has no Bitcoin timestamp proof yet."))
    else:
        try:
            start, atts = ots.read_file(ots_file)
        except ots.OtsError as e:
            v.checks.append(Check("timestamp", False, "The timestamp proof is damaged", str(e)))
            atts, start = [], b""
        if ots_file is not None and start and start != h:
            v.checks.append(
                Check("timestamp", False, "The timestamp is for another record",
                      "The proof does not start from this record's hash.")
            )
        elif start:
            btc = [a for a in atts if a.kind == "bitcoin"]
            if not btc:
                v.checks.append(
                    Check("timestamp", None, "Timestamp waiting for Bitcoin",
                          "The proof is valid but not yet anchored in a Bitcoin block.")
                )
            elif block_lookup is None:
                v.checks.append(
                    Check("timestamp", None, f"Claims Bitcoin block {btc[0].height}",
                          "Offline: the block was not looked up, so the claim was not confirmed.")
                )
            else:
                confirmed = None
                for a in btc:
                    found = block_lookup(a.height)
                    if found and a.digest[::-1].hex() == found[0].lower():
                        confirmed = (a.height, found[1])
                        break
                v.checks.append(
                    Check("timestamp", True, f"Existed by {_day(confirmed[1])}",
                          f"The record is committed in Bitcoin block {confirmed[0]}, mined on {_day(confirmed[1])}. "
                          "Nobody, including Mivia, can backdate it.")
                    if confirmed
                    else Check("timestamp", False, "The Bitcoin block does not match",
                               f"The proof points to block {btc[0].height}, but that block does not contain it.")
                )

    # 5. The watermark payload belongs to this record.
    payload_hex = files.get("1-registration/watermark-payload.hex")
    if payload_hex is None:
        v.checks.append(
            Check("watermark", None, "No watermark payload",
                  "This record has no watermark payload in the pack (normal for DAW plug-in registrations).")
        )
    else:
        try:
            p = bytes.fromhex(payload_hex.decode().strip())
        except ValueError:
            p = b""
        wm_ok = (
            len(p) == 20
            and p[0] == 0xFB
            and _crc16(p[:18]) == int.from_bytes(p[18:20], "big")
            and p[6:14] == h[:8]
            and pack_keys is not None
            and p[2:6] == blake3.blake3(pack_keys.platform).digest()[:4]
        )
        v.checks.append(
            Check(
                "watermark",
                wm_ok,
                "The watermark payload points to this record" if wm_ok else "The watermark payload does not match",
                "The payload embedded in the audio carries this record's id and Mivia's issuer id. Reading it "
                "from an audio file needs Mivia's decoder or the public scan on mivia.co."
                if wm_ok
                else "The payload in the pack does not point to this record.",
            )
        )

    # 6. Mivia's dated statement.
    st = files.get("2-statement/statement.json")
    if st is None or v.statement is None:
        v.checks.append(Check("statement", False, "Statement missing", "No readable 2-statement/statement.json."))
    else:
        s_ok = _verify_sig(files.get("2-statement/statement.sig"), st, pack_keys and pack_keys.statement)
        listed = v.statement.get("files", [])
        others = sorted(n for n in files if not n.startswith("2-statement/"))
        list_ok = [f.get("path") for f in listed] == others and all(
            hashlib.sha256(files[f["path"]]).hexdigest() == f.get("sha256") for f in listed
        )
        ok = s_ok and list_ok
        v.checks.append(
            Check(
                "statement",
                ok,
                f"Mivia's statement of {str(v.statement.get('generated_utc', ''))[:10]} is genuine"
                if ok
                else "The statement does not match the pack",
                "The statement is signed by Mivia and covers every other file in the pack. It is Mivia's "
                "account of the record on that date; a later pack may say more (for example, a dispute)."
                if ok
                else ("The statement's signature is not valid." if not s_ok
                      else "Files were added, removed or changed after the statement was signed."),
            )
        )

    # 7. The audio file: exact match where the record has the file's hash, fingerprint otherwise too.
    if audio_path:
        with open(audio_path, "rb") as fh:
            got = hashlib.sha256(fh.read()).hexdigest()
        want = ((v.manifest.get("extensions") or {}).get("audio") or {}).get("file_sha256")
        if want:
            v.checks.append(
                Check("audio", True, "This is the exact file that was registered",
                      f"Its SHA-256 ({got}) is the one signed in the record.")
                if want == got
                else Check("audio", False, "Not the exact registered file",
                           "This file is not byte-for-byte the registered one. See the fingerprint check.")
            )
        registered = files.get("1-registration/fingerprint.chromaprint")
        if registered is None:
            v.checks.append(Check("fingerprint", None, "No registered fingerprint",
                                  "This record has no fingerprint in the pack."))
        else:
            fp = fpcalc_fingerprint(audio_path)
            if fp is None:
                v.checks.append(
                    Check("fingerprint", None, "Fingerprint not compared",
                          "Install Chromaprint's fpcalc (https://acoustid.org/chromaprint) to compare the audio.")
                )
            elif len(fp) < FP_MIN_OVERLAP_FRAMES or len(_u32s(registered)) < FP_MIN_OVERLAP_FRAMES:
                v.checks.append(Check("fingerprint", None, "Audio too short to compare",
                                      "At least 10 seconds of overlap are needed."))
            else:
                score = alignment_score(fp, _u32s(registered))
                match = score < FP_MATCH_THRESHOLD
                v.checks.append(
                    Check(
                        "fingerprint",
                        match,
                        "The audio matches the registered recording" if match
                        else "The audio does not match the registered recording",
                        f"Chromaprint bit-error rate {score:.3f} (a match is below {FP_MATCH_THRESHOLD}). "
                        "This is a similarity measure: it also matches re-encoded or edited copies.",
                    )
                )
    return v
