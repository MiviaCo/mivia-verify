"""mivia-verify: check a Mivia evidence pack from the command line."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.request
from typing import Optional, Tuple

from . import __version__, keys
from .verify import verify_pack

MARK = {True: "PASS", False: "FAIL", None: "----"}


def mempool_block(height: int) -> Optional[Tuple[str, int]]:
    """Merkle root and time of a block, from a public block explorer."""
    for base in ("https://mempool.space/api", "https://blockstream.info/api"):
        try:
            with urllib.request.urlopen(f"{base}/block-height/{height}", timeout=15) as r:
                block_hash = r.read().decode().strip()
            with urllib.request.urlopen(f"{base}/block/{block_hash}", timeout=15) as r:
                b = json.load(r)
            return b["merkle_root"], int(b["timestamp"])
        except Exception:
            continue
    return None


def node_block(height: int) -> Optional[Tuple[str, int]]:
    """Merkle root and time of a block, from your own Bitcoin node (bitcoin-cli)."""
    try:
        h = subprocess.run(["bitcoin-cli", "getblockhash", str(height)], capture_output=True, check=True, text=True)
        b = subprocess.run(["bitcoin-cli", "getblockheader", h.stdout.strip()], capture_output=True, check=True, text=True)
        j = json.loads(b.stdout)
        return j["merkleroot"], int(j["time"])
    except Exception:
        return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="mivia-verify",
        description="Check a Mivia evidence pack without relying on Mivia.",
    )
    ap.add_argument("pack", help="the evidence pack (.zip)")
    ap.add_argument("--audio", help="an audio file to compare with the registered recording")
    ap.add_argument("--offline", action="store_true", help="no network: skip the published-key and Bitcoin lookups")
    ap.add_argument("--bitcoin-node", action="store_true", help="look blocks up with your own node (bitcoin-cli)")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    ap.add_argument("--version", action="version", version=f"mivia-verify {__version__}")
    a = ap.parse_args(argv)

    with open(a.pack, "rb") as fh:
        pack = fh.read()
    lookup = None if a.offline else (node_block if a.bitcoin_node else mempool_block)
    v = verify_pack(
        pack,
        audio_path=a.audio,
        published=None if a.offline else keys.published(),
        pinned=keys.pinned(),
        block_lookup=lookup,
    )

    if a.json:
        print(json.dumps({
            "record_id": v.record_id,
            "passed": not v.failed,
            "checks": [c.__dict__ for c in v.checks],
        }, indent=2))
        return 1 if v.failed else 0

    m = v.manifest
    print(f"Mivia evidence pack, record {v.record_id}")
    if m.get("title"):
        print(f'"{m.get("title")}" registered by {m.get("creator")} on {str(m.get("created_utc", ""))[:10]}')
    print()
    for c in v.checks:
        print(f"[{MARK[c.ok]}] {c.title}")
        print(f"       {c.detail}")
    print()
    print("Result:", "FAILED: do not rely on this pack." if v.failed else "every check that could run passed.")
    print("A pack shows what was registered, by which account, and since when.")
    print("It does not prove who wrote the music or who owns it.")
    return 1 if v.failed else 0


if __name__ == "__main__":
    sys.exit(main())
