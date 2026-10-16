"""Tests build packs the way mivia.co does (functions/_lib/evidence.ts) and tamper with them."""

import hashlib
import io
import json
import os
import zipfile
from pathlib import Path

import blake3
import pytest
from nacl.signing import SigningKey

from mivia_verify import Keys, verify_pack
from mivia_verify import ots as ots_mod

PLATFORM = SigningKey(bytes([7]) * 32)
STATEMENT = SigningKey(bytes([9]) * 32)
KEYS = Keys(bytes(PLATFORM.verify_key), bytes(STATEMENT.verify_key))
AUDIO = b"RIFF....fake wav bytes"


def canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


MANIFEST = canonical({
    "created_utc": "2026-10-15T12:00:00Z",
    "creator": "Artist",
    "extensions": {"audio": {"file_sha256": hashlib.sha256(AUDIO).hexdigest()}},
    "title": "Song",
})
H = blake3.blake3(MANIFEST).digest()
APPEND = bytes([3]) * 16
TREE = bytes([0xF0, 16]) + APPEND + bytes([0x08, 0x00]) + ots_mod.BITCOIN + bytes([3, 0xA0, 0xF7, 0x36])
MERKLE = hashlib.sha256(H + APPEND).digest()


def lookup(height):
    return (MERKLE[::-1].hex(), 1760500000) if height == 900000 else None


def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def payload():
    p = bytes([0xFB, 5]) + blake3.blake3(KEYS.platform).digest()[:4] + H[:8] + bytes(4)
    return p + crc16(p).to_bytes(2, "big")


def files():
    import base64
    keys = {"keys": {
        "platform": {"public_key_b64": base64.b64encode(KEYS.platform).decode()},
        "statement": {"public_key_b64": base64.b64encode(KEYS.statement).decode()},
    }}
    f = {
        "1-registration/manifest.json": MANIFEST,
        "1-registration/manifest.sig": PLATFORM.sign(MANIFEST).signature,
        "1-registration/timestamp.ots": ots_mod.HEADER_MAGIC + b"\x01\x08" + H + TREE,
        "1-registration/watermark-payload.hex": (payload().hex() + "\n").encode(),
        "3-keys/mivia-keys.json": json.dumps(keys).encode(),
        "README.txt": b"readme",
    }
    return f


def seal(f):
    st = canonical({
        "generated_utc": "2026-10-20T09:00:00.000Z",
        "record": {"id": H[:8].hex(), "manifest_blake3": H.hex()},
        "files": [{"path": p, "sha256": hashlib.sha256(f[p]).hexdigest()} for p in sorted(f)],
    })
    f["2-statement/statement.json"] = st
    f["2-statement/statement.sig"] = STATEMENT.sign(st).signature
    return f


def zipped(f):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for k, v in f.items():
            z.writestr(k, v)
    return buf.getvalue()


def results(v):
    return {c.id: c.ok for c in v.checks}


@pytest.fixture
def audio(tmp_path):
    p = tmp_path / "song.wav"
    p.write_bytes(AUDIO)
    return str(p)


def test_genuine_pack_passes(audio):
    v = verify_pack(zipped(seal(files())), audio_path=audio, published=KEYS, pinned=KEYS, block_lookup=lookup)
    assert results(v) == {
        "record": True, "signature": True, "keys": True, "timestamp": True,
        "watermark": True, "statement": True, "audio": True, "fingerprint": None,
    }
    assert v.record_id == H[:8].hex()
    assert not v.failed


def test_one_changed_byte_in_the_record_fails():
    f = files()
    m = bytearray(f["1-registration/manifest.json"])
    m[10] ^= 1
    f["1-registration/manifest.json"] = bytes(m)
    r = results(verify_pack(zipped(seal(files()) | {"1-registration/manifest.json": bytes(m)}), published=KEYS, block_lookup=lookup))
    assert r["record"] is False and r["signature"] is False and r["timestamp"] is False and r["statement"] is False


def test_edited_statement_fails():
    f = seal(files())
    f["2-statement/statement.json"] = f["2-statement/statement.json"].replace(b"2026-10-20", b"2026-10-21")
    assert results(verify_pack(zipped(f), published=KEYS))["statement"] is False


def test_added_file_fails():
    f = seal(files())
    f["extra.txt"] = b"hi"
    assert results(verify_pack(zipped(f), published=KEYS))["statement"] is False


def test_keys_that_differ_from_either_reference_fail():
    other = Keys(bytes(SigningKey(bytes([1]) * 32).verify_key), KEYS.statement)
    v = verify_pack(zipped(seal(files())), published=KEYS, pinned=other)
    assert results(v)["keys"] is False


def test_wrong_bitcoin_block_fails():
    v = verify_pack(zipped(seal(files())), published=KEYS, block_lookup=lambda h: ("00" * 32, 1))
    assert results(v)["timestamp"] is False


def test_a_different_audio_file_fails(tmp_path):
    p = tmp_path / "other.wav"
    p.write_bytes(b"other")
    assert results(verify_pack(zipped(seal(files())), audio_path=str(p), published=KEYS))["audio"] is False


def test_offline_reports_unchecked_not_failed():
    r = results(verify_pack(zipped(seal(files()))))
    assert r["keys"] is None and r["timestamp"] is None


def test_not_a_pack():
    assert verify_pack(b"not a zip").failed


def test_pack_built_by_the_website_verifies():
    """A pack downloaded from a local run of mivia.co (local test keys)."""
    pack = (Path(__file__).parent / "vectors" / "website-pack.zip").read_bytes()
    r = results(verify_pack(pack))
    assert r["record"] is True and r["signature"] is True and r["statement"] is True


def test_alignment_score_identical_and_unrelated():
    from mivia_verify.verify import alignment_score
    a = [int.from_bytes(os.urandom(4), "little") for _ in range(200)]
    b = [int.from_bytes(os.urandom(4), "little") for _ in range(200)]
    assert alignment_score(a, a) == 0
    assert alignment_score(a, b) > 0.35
