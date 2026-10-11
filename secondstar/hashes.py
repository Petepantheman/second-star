"""The two template hashes a covenant leaf can commit to.

BIP-119 (OP_CHECKTEMPLATEVERIFY) and BIP-446 (OP_TEMPLATEHASH) both hash the parts of a transaction that decide
where the money goes: version, locktime, every input's nSequence, every output. Neither hashes the coin being
spent, which is why a whole chain of templates can be written before any of it is funded.

Both functions are checked against the official vectors in tests/vectors.
"""
from __future__ import annotations

import struct

from .tx import Tx, sha256, ser_output, ser_string


def tagged_hash(tag: str, msg: bytes) -> bytes:
    t = sha256(tag.encode())
    return sha256(t + t + msg)


def ctv_hash(tx: Tx, input_index: int) -> bytes:
    """BIP-119 DefaultCheckTemplateVerifyHash: version, locktime, scriptSigs (only if any is non-empty), input
    count, every nSequence, output count, every output, input index."""
    r = struct.pack("<I", tx.version & 0xFFFFFFFF) + struct.pack("<I", tx.locktime & 0xFFFFFFFF)
    if any(i.script_sig for i in tx.vin):
        r += sha256(b"".join(ser_string(i.script_sig) for i in tx.vin))
    r += struct.pack("<I", len(tx.vin))
    r += sha256(b"".join(struct.pack("<I", i.sequence) for i in tx.vin))
    r += struct.pack("<I", len(tx.vout))
    r += sha256(b"".join(ser_output(o) for o in tx.vout))
    r += struct.pack("<I", input_index)
    return sha256(r)


def template_hash(tx: Tx, input_index: int, annex: bytes | None = None) -> bytes:
    """BIP-446 template hash: tagged hash 'TemplateHash' of version, locktime, sha_sequences, sha_outputs,
    annex_present, input index, and sha_annex when an annex is present."""
    msg = struct.pack("<I", tx.version & 0xFFFFFFFF) + struct.pack("<I", tx.locktime & 0xFFFFFFFF)
    msg += sha256(b"".join(struct.pack("<I", i.sequence) for i in tx.vin))
    msg += sha256(b"".join(ser_output(o) for o in tx.vout))
    msg += bytes([0 if annex is None else 1])
    msg += struct.pack("<I", input_index)
    if annex is not None:
        msg += sha256(ser_string(annex))
    return tagged_hash("TemplateHash", msg)
