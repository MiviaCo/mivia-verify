"""Minimal OpenTimestamps proof reader.

Walks a .ots proof from its starting digest and returns every attestation
reached, with the digest at that point. For a Bitcoin attestation that
digest is the merkle root of the block it names. Wire format:
https://github.com/opentimestamps/python-opentimestamps (core/serialize.py,
core/timestamp.py, core/op.py, core/notary.py).

Kept dependency-free on purpose so the whole check can be read in one
sitting. The standard client gives the same answer:
    ots verify -d <BLAKE3 hex of manifest.json> timestamp.ots
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List, Optional

HEADER_MAGIC = (
    b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
)
VERSION = 1
OP_SHA256 = 0x08

BITCOIN = bytes.fromhex("0588960d73d71901")
PENDING = bytes.fromhex("83dfe30d2ef90c8e")


class OtsError(ValueError):
    pass


@dataclass
class Attestation:
    kind: str  # "bitcoin", "pending" or "unknown"
    digest: bytes
    height: Optional[int] = None
    url: Optional[str] = None


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def byte(self) -> int:
        if self.eof():
            raise OtsError("unexpected end of proof")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def peek(self) -> int:
        if self.eof():
            raise OtsError("unexpected end of proof")
        return self.data[self.pos]

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise OtsError("unexpected end of proof")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def varuint(self) -> int:
        value, shift = 0, 0
        while True:
            b = self.byte()
            value |= (b & 0x7F) << shift
            if not b & 0x80:
                return value
            shift += 7
            if shift > 63:
                raise OtsError("varuint too long")

    def varbytes(self) -> bytes:
        return self.take(self.varuint())


def _apply(tag: int, r: _Reader, digest: bytes) -> bytes:
    if tag == 0x08:
        return hashlib.sha256(digest).digest()
    if tag == 0x02:
        return hashlib.sha1(digest).digest()
    if tag == 0x03:
        return hashlib.new("ripemd160", digest).digest()
    if tag == 0xF0:
        return digest + r.varbytes()
    if tag == 0xF1:
        return r.varbytes() + digest
    if tag == 0xF2:
        return digest[::-1]
    if tag == 0xF3:
        return digest.hex().encode()
    raise OtsError(f"unsupported operation 0x{tag:02x}")


def _walk(r: _Reader, digest: bytes, out: List[Attestation]) -> None:
    while True:
        tag = r.byte()
        if tag == 0x00:
            magic = r.take(8)
            payload = r.varbytes()
            if magic == BITCOIN:
                out.append(Attestation("bitcoin", digest, height=_Reader(payload).varuint()))
            elif magic == PENDING:
                p = _Reader(payload)
                out.append(Attestation("pending", digest, url=p.varbytes().decode("utf-8", "replace")))
            else:
                out.append(Attestation("unknown", digest))
        else:
            _walk(r, _apply(tag, r, digest), out)
        if r.eof() or r.peek() != 0xFF:
            return
        r.byte()


def read_file(ots_file: bytes) -> tuple[bytes, List[Attestation]]:
    """Parse a complete .ots file. Returns (the digest it starts from, attestations)."""
    r = _Reader(ots_file)
    if r.take(len(HEADER_MAGIC)) != HEADER_MAGIC:
        raise OtsError("not an OpenTimestamps file")
    if r.varuint() != VERSION:
        raise OtsError("unsupported OpenTimestamps version")
    if r.byte() != OP_SHA256:
        raise OtsError("unexpected file hash operation")
    digest = r.take(32)
    atts: List[Attestation] = []
    _walk(r, digest, atts)
    return digest, atts
