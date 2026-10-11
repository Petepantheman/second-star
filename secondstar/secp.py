"""secp256k1, BIP-340 Schnorr and BIP-341 Taproot in plain Python. Test networks only: slow on purpose, small on
purpose, and not hardened against side channels. Checked against the BIP-340 vectors in tests/vectors."""
from __future__ import annotations

import hashlib

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
# BIP-341's suggested provably-unspendable internal key: lift_x(sha256(G_x)). Nobody knows its discrete log.
NUMS_X = 0x50929B74C1A04954B78B4B6035E97A5E078A5A0F28EC96D547BFEE9ACE803AC0
LEAF_VERSION = 0xC0


def tagged_hash(tag: str, msg: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


# ---- curve --------------------------------------------------------------------------------------------------
def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = 3 * x1 * x1 * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def mul(k: int, p=G):
    r = None
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def lift_x(x: int):
    if x >= P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    return x, y if y % 2 == 0 else P - y


def xonly(point) -> bytes:
    return point[0].to_bytes(32, "big")


def pubkey(secret: int) -> bytes:
    return xonly(mul(secret))


# ---- BIP-340 ------------------------------------------------------------------------------------------------
def sign(msg: bytes, secret: int, aux: bytes = b"\x00" * 32) -> bytes:
    if not (1 <= secret < N):
        raise ValueError("secret out of range")
    pt = mul(secret)
    d = secret if pt[1] % 2 == 0 else N - secret
    t = (d ^ int.from_bytes(tagged_hash("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(tagged_hash("BIP0340/nonce", t + xonly(pt) + msg), "big") % N
    if k0 == 0:
        raise ValueError("bad nonce")
    r = mul(k0)
    k = k0 if r[1] % 2 == 0 else N - k0
    e = int.from_bytes(tagged_hash("BIP0340/challenge", xonly(r) + xonly(pt) + msg), "big") % N
    sig = xonly(r) + ((k + e * d) % N).to_bytes(32, "big")
    if not verify(msg, xonly(pt), sig):
        raise ValueError("signature failed self-check")
    return sig


def verify(msg: bytes, pk: bytes, sig: bytes) -> bool:
    if len(pk) != 32 or len(sig) != 64:
        return False
    pt = lift_x(int.from_bytes(pk, "big"))
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if pt is None or r >= P or s >= N:
        return False
    e = int.from_bytes(tagged_hash("BIP0340/challenge", sig[:32] + pk + msg), "big") % N
    R = _add(mul(s), mul(N - e, pt))
    return R is not None and R[1] % 2 == 0 and R[0] == r


# ---- BIP-341 ------------------------------------------------------------------------------------------------
def leaf_hash(script: bytes, version: int = LEAF_VERSION) -> bytes:
    from .tx import ser_string
    return tagged_hash("TapLeaf", bytes([version]) + ser_string(script))


def branch_hash(a: bytes, b: bytes) -> bytes:
    return tagged_hash("TapBranch", a + b if a < b else b + a)


def taproot_output(internal_x: bytes, merkle_root: bytes) -> tuple[bytes, int]:
    """(output x-only key, parity) for an internal key tweaked with the tree root."""
    t = int.from_bytes(tagged_hash("TapTweak", internal_x + merkle_root), "big")
    if t >= N:
        raise ValueError("tweak out of range")
    pt = lift_x(int.from_bytes(internal_x, "big"))
    q = _add(pt, mul(t))
    return xonly(q), q[1] % 2


def script_tree(scripts: list[bytes], internal_x: bytes | None = None) -> dict:
    """A Taproot output whose leaves are exactly `scripts`, in the order given. Adjacent nodes are paired; an odd
    last node is promoted, not duplicated. The control-block siblings recompute the same root, which is what the
    node checks. For two scripts this is the same tree as two_leaf_tree."""
    if not scripts:
        raise ValueError("a taproot tree needs a leaf")
    internal_x = internal_x or NUMS_X.to_bytes(32, "big")
    leaves = [{"hash": leaf_hash(s), "script": s, "sibs": []} for s in scripts]
    groups = [{"hash": leaf["hash"], "leaves": [leaf], "shape": i} for i, leaf in enumerate(leaves)]
    while len(groups) > 1:
        nxt = []
        i = 0
        while i < len(groups):
            if i + 1 == len(groups):
                nxt.append(groups[i])
                i += 1
                continue
            a, b = groups[i], groups[i + 1]
            parent = branch_hash(a["hash"], b["hash"])
            for leaf in a["leaves"]:
                leaf["sibs"].append(b["hash"])
            for leaf in b["leaves"]:
                leaf["sibs"].append(a["hash"])
            nxt.append({"hash": parent, "leaves": a["leaves"] + b["leaves"], "shape": [a["shape"], b["shape"]]})
            i += 2
        groups = nxt
    root = groups[0]["hash"]
    for leaf in leaves:
        h = leaf["hash"]
        for sib in leaf["sibs"]:
            h = branch_hash(h, sib)
        if h != root:
            raise ValueError("control path does not recompute the merkle root")
    out_x, parity = taproot_output(internal_x, root)
    first = bytes([LEAF_VERSION | parity]) + internal_x
    return {"script_pubkey": bytes([0x51, 0x20]) + out_x, "output_key": out_x, "root": root,
            "control": {leaf["script"]: first + b"".join(leaf["sibs"]) for leaf in leaves},
            "leaf_hash": {leaf["script"]: leaf["hash"] for leaf in leaves}, "shape": groups[0]["shape"]}


def sighash_script_path(tx, input_index: int, prevouts: list, leaf: bytes) -> bytes:
    """BIP-341 signature hash, SIGHASH_DEFAULT, script-path spend. `prevouts` = [(value, script_pubkey)] for every
    input, in order."""
    import struct
    from .tx import ser_output, ser_string
    sha = hashlib.sha256
    msg = b"\x00"  # hash_type SIGHASH_DEFAULT
    msg += struct.pack("<I", tx.version & 0xFFFFFFFF) + struct.pack("<I", tx.locktime & 0xFFFFFFFF)
    msg += sha(b"".join(bytes.fromhex(i.txid)[::-1] + struct.pack("<I", i.vout) for i in tx.vin)).digest()
    msg += sha(b"".join(struct.pack("<q", v) for v, _ in prevouts)).digest()
    msg += sha(b"".join(ser_string(spk) for _, spk in prevouts)).digest()
    msg += sha(b"".join(struct.pack("<I", i.sequence) for i in tx.vin)).digest()
    msg += sha(b"".join(ser_output(o) for o in tx.vout)).digest()
    msg += bytes([2])  # spend_type: ext_flag 1 (script path), no annex
    msg += struct.pack("<I", input_index)
    msg += leaf + b"\x00" + b"\xff\xff\xff\xff"  # tapleaf hash, key version, codeseparator position
    return tagged_hash("TapSighash", b"\x00" + msg)
