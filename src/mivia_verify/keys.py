"""Mivia's public keys, pinned in this repository.

The verifier compares the keys inside a pack with this copy and with the
one published at https://mivia.co/.well-known/mivia-keys.json. Two
independent copies: changing one is not enough to make a forged pack pass.

Filled in for each release from the production keys; None means this
build has no pinned copy (development only).
"""

from __future__ import annotations

import base64
import json
import urllib.request
from typing import Optional

from .verify import Keys

PLATFORM_KEY_B64: Optional[str] = None
STATEMENT_KEY_B64: Optional[str] = None

PUBLISHED_URL = "https://mivia.co/.well-known/mivia-keys.json"


def pinned() -> Optional[Keys]:
    if not PLATFORM_KEY_B64 or not STATEMENT_KEY_B64:
        return None
    return Keys(base64.b64decode(PLATFORM_KEY_B64), base64.b64decode(STATEMENT_KEY_B64))


def published(url: str = PUBLISHED_URL, timeout: float = 10) -> Optional[Keys]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            k = json.load(r)["keys"]
        return Keys(
            base64.b64decode(k["platform"]["public_key_b64"]),
            base64.b64decode(k["statement"]["public_key_b64"]),
        )
    except Exception:
        return None
