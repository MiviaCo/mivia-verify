"""Mivia's public keys, pinned in this repository.

The verifier compares the keys inside a pack with this copy and with the
one published at https://mivia.co/.well-known/mivia-keys.json. Two
independent copies: changing one is not enough to make a forged pack pass.

Production keys, published 2026-10-16. The platform key was read from
decode.mivia.co/healthz and matches the issuer id (447fb581) in every web
registration's watermark payload. A rotated key is added here, never
removed, so older packs keep verifying.
"""

from __future__ import annotations

import base64
import json
import urllib.request
from typing import List, Optional, Tuple

from .verify import Keys, parse_keys_file

PLATFORM_KEY_B64: Optional[str] = "1Z5ayax4CYcVDDVfmWaAaCwATMmBEH77gKVRB4kOEUc="  # the watermark key
STATEMENT_KEY_B64: Optional[str] = "APm0sr6P9ctu6IkiFzq/IsFjZuG8/TJh+0zaAJfR4w0="

PUBLISHED_URL = "https://mivia.co/.well-known/mivia-keys.json"


# The watermark key derives every watermark and is never rotated. Signing
# keys can be rotated: list every one, never delete an entry, mark a leaked
# key "revoked". Before the first rotation the platform key does both jobs.
WATERMARK_KEY_B64: Optional[str] = PLATFORM_KEY_B64
SIGNING_KEYS: List[Tuple[str, str]] = [  # (public key, status)
    # The original key: signed every manifest until 2026-10-16 04:24:30 UTC.
    ("1Z5ayax4CYcVDDVfmWaAaCwATMmBEH77gKVRB4kOEUc=", "retired"),
    # First rotated signing key, active from 2026-10-16 04:24:30 UTC.
    ("1h+uS4+O3iNe6BSpOkod/6zUQCQ44E4iJoBp+dUjsO8=", "active"),
]


def pinned() -> Optional[Keys]:
    if not PLATFORM_KEY_B64 or not STATEMENT_KEY_B64:
        return None
    active = next((k for k, st in SIGNING_KEYS if st == "active"), PLATFORM_KEY_B64)
    return Keys(
        base64.b64decode(active),
        base64.b64decode(STATEMENT_KEY_B64),
        base64.b64decode(WATERMARK_KEY_B64 or PLATFORM_KEY_B64),
        [(base64.b64decode(k), st) for k, st in SIGNING_KEYS],
    )


def published(url: str = PUBLISHED_URL, timeout: float = 10) -> Optional[Keys]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return parse_keys_file(json.load(r))
    except Exception:
        return None
