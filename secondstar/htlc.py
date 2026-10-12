"""The swap lock: how a vault tranche becomes Lightning balance without the agent holding an on-chain key.

The vault pays a tranche into a Taproot output whose internal key is the BIP-341 NUMS point (nobody knows its secret,
so in practice there is no key path) and whose tree has two leaves:

  claim   OP_SHA256 <h> OP_EQUALVERIFY <provider key> OP_CHECKSIG     the provider, with the preimage of h
  refund  <r> OP_CHECKSEQUENCEVERIFY OP_DROP <owner key> OP_CHECKSIG   the owner, after r blocks

The owner's signer keeps the seed the preimages come from. While the signer keeps it safe, the provider can only learn a
preimage by paying a Lightning invoice with payment hash h, so it can claim the on-chain coins only after that payment
settles. That works once per lock: after a claim the preimage is public, which is why each swap vault is funded once.
If the provider never pays, the coins go back to the owner, not to the agent. (In the naive design of lightning_run the
agent's node holds the preimage instead; that is the design that gets robbed.)
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from . import secp
from .tx import Tx, TxIn, TxOut

OP_SHA256, OP_EQUALVERIFY, OP_CHECKSIG, OP_CSV, OP_DROP = 0xA8, 0x88, 0xAC, 0xB2, 0x75


def script_num(n: int) -> bytes:
    """Minimal push of a small non-negative number (BIP-62 minimal encoding)."""
    if n == 0:
        return bytes([0x00])
    if 1 <= n <= 16:
        return bytes([0x50 + n])
    body = bytearray()
    while n:
        body.append(n & 0xFF)
        n >>= 8
    if body[-1] & 0x80:
        body.append(0)
    return bytes([len(body)]) + bytes(body)


def claim_leaf(payment_hash: bytes, provider_x: bytes) -> bytes:
    assert len(payment_hash) == 32 and len(provider_x) == 32
    return (bytes([OP_SHA256, 0x20]) + payment_hash + bytes([OP_EQUALVERIFY, 0x20]) + provider_x
            + bytes([OP_CHECKSIG]))


def refund_leaf(r: int, owner_x: bytes) -> bytes:
    if not 1 <= r <= 0xFFFF:
        raise ValueError("refund delay must be 1..65535 blocks")
    assert len(owner_x) == 32
    return script_num(r) + bytes([OP_CSV, OP_DROP, 0x20]) + owner_x + bytes([OP_CHECKSIG])


@dataclass
class SwapLock:
    payment_hash: bytes
    provider_x: bytes
    owner_x: bytes
    refund_delay: int
    script_pubkey: bytes
    claim: bytes
    refund: bytes
    control: dict
    leaf_hash: dict


def lock(payment_hash: bytes, provider_x: bytes, owner_x: bytes, refund_delay: int) -> SwapLock:
    claim, refund = claim_leaf(payment_hash, provider_x), refund_leaf(refund_delay, owner_x)
    tree = secp.script_tree([claim, refund])
    return SwapLock(payment_hash, provider_x, owner_x, refund_delay, tree["script_pubkey"], claim, refund,
                    tree["control"], tree["leaf_hash"])


def preimage_pair(seed: bytes, k: int) -> tuple[bytes, bytes]:
    """The k-th (preimage, payment hash) from a secret seed. The owner's signer keeps the seed; the vault and the
    invoices carry only hashes."""
    p = hashlib.sha256(b"second-star/swap/" + seed + k.to_bytes(4, "big")).digest()
    return p, hashlib.sha256(p).digest()


def claim_tx(sl: SwapLock, prev: tuple[str, int], value: int, to_spk: bytes, fee: int, provider_secret: int,
             preimage: bytes) -> Tx:
    tx = Tx(2, 0, [TxIn(prev[0], prev[1], b"", 0xFFFFFFFF)], [TxOut(value - fee, to_spk)])
    digest = secp.sighash_script_path(tx, 0, [(value, sl.script_pubkey)], sl.leaf_hash[sl.claim])
    tx.witness = [[secp.sign(digest, provider_secret), preimage, sl.claim, sl.control[sl.claim]]]
    return tx


def refund_tx(sl: SwapLock, prev: tuple[str, int], value: int, to_spk: bytes, fee: int, owner_secret: int,
              sequence: int | None = None) -> Tx:
    seq = sl.refund_delay if sequence is None else sequence
    tx = Tx(2, 0, [TxIn(prev[0], prev[1], b"", seq)], [TxOut(value - fee, to_spk)])
    digest = secp.sighash_script_path(tx, 0, [(value, sl.script_pubkey)], sl.leaf_hash[sl.refund])
    tx.witness = [[secp.sign(digest, owner_secret), sl.refund, sl.control[sl.refund]]]
    return tx


def describe(locks: list[SwapLock]) -> list[dict]:
    """The parts of each lock, for the prover's claims (claims["swap_locks"])."""
    return [{"payment_hash": lk.payment_hash.hex(), "provider_key": lk.provider_x.hex(), "owner_key": lk.owner_x.hex(),
             "refund_delay": lk.refund_delay} for lk in locks]
