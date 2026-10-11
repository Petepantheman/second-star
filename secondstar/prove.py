"""The prover: reads a vault from its raw bytes and checks every state it can ever reach.

This file shares no code with the builder. It has its own transaction parser, its own CTV and TEMPLATEHASH hashes,
its own Taproot tree and tweak arithmetic, and it derives the unspendable internal key from the curve's generator
itself. If the builder has a bug, this file is meant to catch it rather than repeat it.

What it checks, for every vault reachable from the root:
  1. The address is a Taproot output whose internal key is the BIP-341 unspendable point, so no key-path spend.
  2. The tree, rebuilt from the listed leaves alone, gives exactly that address. No hidden leaf can exist.
  3. Every leaf is one of three exact byte patterns: a CTV covenant, a TEMPLATEHASH covenant, or the owner's key.
     Anything else fails, because an unknown leaf could be a back door.
  4. Each covenant hash is the hash of a listed transaction, so that transaction is the only way through the leaf.
  5. That transaction has one input, nLockTime 0, a relative timelock of exactly `delay` blocks, and outputs that go
     only to a menu address (at most `tranche`), to at most one next vault, to the owner's cold address, or to a
     0-value anchor. Its outputs add up to exactly what the vault holds.
  6. The owner's leaf is reachable: no leaf sits deeper than BIP-341's limit of 128, and the owner key is a valid
     curve point.
Then it walks every path through the vault graph and computes the most the menu can be paid after k steps.

The result is a statement about these bytes under four assumptions, written out in PROOF.md.

    python -m secondstar.prove vault.json claims.json
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys

# ---- curve (secp256k1), only what a Taproot tweak needs ----------------------------------------------------
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _pt_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % _P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], _P - 2, _P) % _P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], _P - 2, _P) % _P
    x = (lam * lam - a[0] - b[0]) % _P
    return x, (lam * (a[0] - x) - a[1]) % _P


def _pt_mul(k: int, pt):
    acc = None
    while k:
        if k & 1:
            acc = _pt_add(acc, pt)
        pt = _pt_add(pt, pt)
        k >>= 1
    return acc


def _lift_x(x: int):
    if x >= _P:
        return None
    y2 = (pow(x, 3, _P) + 7) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    if y * y % _P != y2:
        return None
    return x, y if y % 2 == 0 else _P - y


def unspendable_key() -> bytes:
    """BIP-341's H: the x coordinate is SHA-256 of the uncompressed encoding of G. Nobody knows its discrete log."""
    g = b"\x04" + _G[0].to_bytes(32, "big") + _G[1].to_bytes(32, "big")
    x = hashlib.sha256(g).digest()
    if _lift_x(int.from_bytes(x, "big")) is None:
        raise AssertionError("H is not on the curve")
    return x


# ---- hashing ------------------------------------------------------------------------------------------------
def _sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _tagged(tag: str, msg: bytes) -> bytes:
    t = _sha(tag.encode())
    return _sha(t + t + msg)


def _compact(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def _leaf(script: bytes) -> bytes:
    return _tagged("TapLeaf", b"\xc0" + _compact(len(script)) + script)


def _branch(a: bytes, b: bytes) -> bytes:
    return _tagged("TapBranch", a + b if a < b else b + a)


def _output_key(internal: bytes, root: bytes) -> bytes:
    t = int.from_bytes(_tagged("TapTweak", internal + root), "big")
    if t >= _N:
        raise ValueError("tweak out of range")
    q = _pt_add(_lift_x(int.from_bytes(internal, "big")), _pt_mul(t, _G))
    return q[0].to_bytes(32, "big")


# ---- transactions (parse only) -------------------------------------------------------------------------------
class _R:
    def __init__(self, b: bytes):
        self.b, self.i = b, 0

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.b):
            raise ValueError("truncated")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def n(self) -> int:
        f = self.take(1)[0]
        if f < 0xFD:
            return f
        return struct.unpack({0xFD: "<H", 0xFE: "<I", 0xFF: "<Q"}[f], self.take({0xFD: 2, 0xFE: 4, 0xFF: 8}[f]))[0]


def _parse(raw: bytes) -> dict:
    r = _R(raw)
    version = struct.unpack("<I", r.take(4))[0]
    count = r.n()
    witness = False
    if count == 0:
        if r.take(1) != b"\x01":
            raise ValueError("bad segwit flag")
        witness = True
        count = r.n()
    ins = []
    for _ in range(count):
        r.take(36)
        script_sig = r.take(r.n())
        ins.append({"script_sig": script_sig, "sequence": struct.unpack("<I", r.take(4))[0]})
    outs = []
    for _ in range(r.n()):
        value = struct.unpack("<q", r.take(8))[0]
        outs.append({"value": value, "spk": r.take(r.n())})
    if witness:
        for _ in range(count):
            for _ in range(r.n()):
                r.take(r.n())
    locktime = struct.unpack("<I", r.take(4))[0]
    if r.i != len(raw):
        raise ValueError("trailing bytes")
    return {"version": version, "locktime": locktime, "ins": ins, "outs": outs}


def _ser_outs(outs) -> bytes:
    return b"".join(struct.pack("<q", o["value"]) + _compact(len(o["spk"])) + o["spk"] for o in outs)


def _seqs(tx) -> bytes:
    return b"".join(struct.pack("<I", i["sequence"]) for i in tx["ins"])


def _ctv(tx, index: int) -> bytes:
    m = struct.pack("<II", tx["version"], tx["locktime"])
    if any(i["script_sig"] for i in tx["ins"]):
        m += _sha(b"".join(_compact(len(i["script_sig"])) + i["script_sig"] for i in tx["ins"]))
    m += struct.pack("<I", len(tx["ins"])) + _sha(_seqs(tx))
    m += struct.pack("<I", len(tx["outs"])) + _sha(_ser_outs(tx["outs"])) + struct.pack("<I", index)
    return _sha(m)


def _templatehash(tx, index: int) -> bytes:
    m = struct.pack("<II", tx["version"], tx["locktime"]) + _sha(_seqs(tx)) + _sha(_ser_outs(tx["outs"]))
    return _tagged("TemplateHash", m + b"\x00" + struct.pack("<I", index))  # annex_present = 0


# ---- the proof -----------------------------------------------------------------------------------------------
ANCHOR = bytes.fromhex("51024e73")
MAX_MONEY = 21_000_000 * 100_000_000
MAX_DEPTH = 128


def _depth(shape) -> int:
    return 0 if isinstance(shape, int) else 1 + max(_depth(shape[0]), _depth(shape[1]))


def _check_claims(claims: dict) -> list[str]:
    bad = []
    for key, low, high in (("funding", 1, MAX_MONEY), ("tranche", 1, MAX_MONEY), ("periods", 1, 10_000),
                           ("delay", 1, 0xFFFF)):
        v = claims.get(key)
        if type(v) is not int or not low <= v <= high:
            bad.append(f"claim {key}={v!r} must be an integer in [{low}, {high}]")
    try:
        menu = [bytes.fromhex(m) for m in claims["menu"]]
        cold = bytes.fromhex(claims["cold"])
        cold_key = bytes.fromhex(claims["cold_key"])
    except (KeyError, TypeError, ValueError) as err:
        return bad + [f"claims are malformed: {err}"]
    if not menu or any(not m for m in menu) or not cold:
        bad.append("claims need a non-empty menu and a non-empty cold script")
    if len(cold_key) != 32 or _lift_x(int.from_bytes(cold_key, "big")) is None:
        bad.append("cold_key is not a valid x-only public key, so the owner could never sign")
    return bad


def _classify(script: bytes, cold_key: bytes):
    if len(script) == 34 and script[0] == 0x20 and script[33] == 0xB3:
        return "ctv", script[1:33]
    if len(script) == 35 and script[0] == 0x20 and script[33] == 0xCE and script[34] == 0x87:
        return "templatehash", script[1:33]
    if len(script) == 34 and script[0] == 0x20 and script[33] == 0xAC:
        return ("cold", None) if script[1:33] == cold_key else ("foreign-key", script[1:33])
    return "unknown", None


def _root_from_shape(shape, leaf_hashes: list[bytes], seen: list[int]) -> bytes:
    if isinstance(shape, int):
        if not 0 <= shape < len(leaf_hashes):
            raise ValueError(f"shape names leaf {shape}, which does not exist")
        seen.append(shape)
        return leaf_hashes[shape]
    if not (isinstance(shape, list) and len(shape) == 2):
        raise ValueError("shape must be a leaf index or a pair")
    return _branch(_root_from_shape(shape[0], leaf_hashes, seen), _root_from_shape(shape[1], leaf_hashes, seen))


def prove(vault: dict, claims: dict) -> dict:
    """Return a certificate. verdict PROVED only if every check passed; otherwise the failures say why."""
    fails: list[str] = _check_claims(claims)
    if fails:
        return {"verdict": "REFUTED", "opcode": vault.get("opcode"), "vaults": 0, "leaves": 0, "covenant_leaves": 0,
                "longest_path": 0, "most_paid_after_k_steps": {}, "statement": "", "failures": fails}
    menu = [bytes.fromhex(m) for m in claims["menu"]]
    cold = bytes.fromhex(claims["cold"])
    cold_key = bytes.fromhex(claims["cold_key"])
    funding, tranche, delay, periods = claims["funding"], claims["tranche"], claims["delay"], claims["periods"]
    opcode = vault.get("opcode")
    if opcode not in ("ctv", "templatehash"):
        fails.append(f"unknown opcode family {opcode!r}")
    if len(set(menu)) != len(menu) or cold in menu:
        fails.append("menu addresses must be distinct and must not include the cold address")
    h = unspendable_key()
    vaults = {k.lower(): v for k, v in vault["vaults"].items()}
    root = vault["root"].lower()
    edges: dict[str, list[tuple[int, str | None]]] = {}   # vault -> [(menu payout, next vault or None)]
    value: dict[str, int] = {root: funding}
    order = [root]
    seen_vaults = set()
    leaves_total = covenant_total = 0
    while order:
        name = order.pop()
        if name in seen_vaults:
            continue
        seen_vaults.add(name)
        tag = f"vault {name[:16]}"
        v = vaults.get(name)
        if v is None:
            fails.append(f"{tag}: reachable but not described")
            continue
        spk = bytes.fromhex(name)
        if len(spk) != 34 or spk[:2] != b"\x51\x20":
            fails.append(f"{tag}: not a Taproot output")
            continue
        if bytes.fromhex(v["internal_key"]) != h:
            fails.append(f"{tag}: internal key is not the unspendable point, so a key-path spend may exist")
            continue
        try:
            scripts = [bytes.fromhex(s) for s in v["leaves"]]
            hashes = [_leaf(s) for s in scripts]
            used: list[int] = []
            root_hash = _root_from_shape(v["shape"], hashes, used)
            depth = _depth(v["shape"])
        except (ValueError, TypeError, KeyError, RecursionError) as err:
            fails.append(f"{tag}: {err}")
            continue
        if depth > MAX_DEPTH:
            fails.append(f"{tag}: tree depth {depth} > {MAX_DEPTH}, so some leaves (maybe the owner's) can never be spent")
            continue
        if sorted(used) != list(range(len(scripts))):
            fails.append(f"{tag}: the shape does not use every leaf exactly once")
            continue
        if _output_key(h, root_hash) != spk[2:]:
            fails.append(f"{tag}: the listed leaves do not produce this address")
            continue
        leaves_total += len(scripts)
        cold_leaves = 0
        edges[name] = []
        for idx, script in enumerate(scripts):
            kind, payload = _classify(script, cold_key)
            if kind == "cold":
                cold_leaves += 1
                continue
            if kind in ("unknown", "foreign-key"):
                fails.append(f"{tag} leaf {idx}: {kind} script {script.hex()[:40]}")
                continue
            if kind != opcode:
                fails.append(f"{tag} leaf {idx}: {kind} leaf in a {opcode} vault")
            covenant_total += 1
            raw = v["templates"].get(str(idx))
            if raw is None:
                fails.append(f"{tag} leaf {idx}: covenant with no listed template")
                continue
            try:
                tx = _parse(bytes.fromhex(raw))
            except (ValueError, KeyError, struct.error) as err:
                fails.append(f"{tag} leaf {idx}: template does not parse ({err})")
                continue
            if len(tx["ins"]) != 1 or tx["ins"][0]["script_sig"]:
                fails.append(f"{tag} leaf {idx}: template must have exactly one input and an empty scriptSig")
                continue
            got = _ctv(tx, 0) if kind == "ctv" else _templatehash(tx, 0)
            if got != payload:
                fails.append(f"{tag} leaf {idx}: hash is not the hash of the listed template")
                continue
            seq = tx["ins"][0]["sequence"]
            if tx["locktime"] != 0:
                fails.append(f"{tag} leaf {idx}: nLockTime {tx['locktime']} could freeze or delay the coins")
            if any(not 0 <= o["value"] <= MAX_MONEY for o in tx["outs"]):
                fails.append(f"{tag} leaf {idx}: an output value is negative or above 21 million BTC")
            if tx["version"] < 2 or seq & (1 << 31) or seq & (1 << 22) or (seq & 0xFFFF) != delay:
                fails.append(f"{tag} leaf {idx}: relative timelock is not exactly {delay} blocks")
            if sum(o["value"] for o in tx["outs"]) != value.get(name):
                fails.append(f"{tag} leaf {idx}: outputs {sum(o['value'] for o in tx['outs'])} "
                             f"!= vault value {value.get(name)}")
            payout, forward = 0, []
            for o in tx["outs"]:
                if o["spk"] == ANCHOR:
                    if o["value"] != 0:
                        fails.append(f"{tag} leaf {idx}: anchor carries {o['value']} sats anyone could take")
                elif o["spk"] in menu:
                    payout += o["value"]
                elif o["spk"] == cold:
                    pass
                elif o["spk"].hex() in vaults:
                    forward.append(o)
                else:
                    fails.append(f"{tag} leaf {idx}: pays {o['spk'].hex()[:24]}, which is not on the menu")
            if payout > tranche:
                fails.append(f"{tag} leaf {idx}: pays the menu {payout}, more than the tranche {tranche}")
            if len(forward) > 1:
                fails.append(f"{tag} leaf {idx}: splits into {len(forward)} vaults, which would multiply the allowance")
            nxt = None
            if forward:
                nxt = forward[0]["spk"].hex()
                if value.setdefault(nxt, forward[0]["value"]) != forward[0]["value"]:
                    fails.append(f"vault {nxt[:16]}: reached with two different amounts")
                order.append(nxt)
            edges[name].append((payout, nxt))
        if cold_leaves != 1:
            fails.append(f"{tag}: {cold_leaves} owner leaves (expected exactly 1)")
    extra = set(vaults) - seen_vaults
    if extra:
        fails.append(f"{len(extra)} described vaults are unreachable from the root")
    best = {}  # vault -> {k: most the menu can receive in exactly k covenant spends}

    def walk(name: str, path: tuple) -> dict:
        if name in path:
            raise ValueError("the vault graph has a cycle")
        if name in best:
            return best[name]
        out: dict[int, int] = {}
        for payout, nxt in edges.get(name, []):
            out[1] = max(out.get(1, 0), payout)
            if nxt is not None:
                for k, p in walk(nxt, path + (name,)).items():
                    out[k + 1] = max(out.get(k + 1, 0), payout + p)
        best[name] = out
        return out

    profile = {}
    if not fails:
        try:
            profile = walk(root, ())
        except ValueError as err:
            fails.append(str(err))
        for k, p in sorted(profile.items()):
            if p > k * tranche:
                fails.append(f"after {k} steps the menu could receive {p} > {k} x {tranche}")
        if profile and max(profile) > periods:
            fails.append(f"a path has {max(profile)} covenant steps, more than {periods} periods")
    return {
        "verdict": "PROVED" if not fails else "REFUTED",
        "opcode": opcode,
        "vaults": len(seen_vaults),
        "leaves": leaves_total,
        "covenant_leaves": covenant_total,
        "longest_path": max(profile) if profile else 0,
        "most_paid_after_k_steps": {str(k): p for k, p in sorted(profile.items())},
        "statement": (f"For one coin of exactly {funding} sats at the root address, and without the owner's key: "
                      f"it can only pay the {len(menu)} menu address(es), at most {tranche} sats per step, at most "
                      f"one step per {delay} blocks, at most {periods} steps; every other sat stays in the vault or "
                      f"goes to the owner's address. Each further coin sent to the address is a separate allowance "
                      f"with the same limits, and sats above {funding} in a coin go to a miner as fee."),
        "failures": fails,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-1].strip())
        return 2
    def no_constants(name):
        raise ValueError(f"{name} is not a number")
    with open(argv[0], encoding="utf-8") as f:
        vault = json.load(f, parse_constant=no_constants)
    with open(argv[1], encoding="utf-8") as f:
        claims = json.load(f, parse_constant=no_constants)
    cert = prove(vault, claims)
    print(json.dumps(cert, indent=2))
    return 0 if cert["verdict"] == "PROVED" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
