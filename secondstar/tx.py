"""Bitcoin transactions: serialize, parse, txid. Standard library only."""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def ser_string(b: bytes) -> bytes:
    return varint(len(b)) + b


@dataclass
class TxIn:
    txid: str = "00" * 32        # display order (big-endian hex)
    vout: int = 0
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFF


@dataclass
class TxOut:
    value: int
    script_pubkey: bytes


def ser_output(o: TxOut) -> bytes:
    return struct.pack("<q", o.value) + ser_string(o.script_pubkey)


@dataclass
class Tx:
    version: int = 2
    locktime: int = 0
    vin: list[TxIn] = field(default_factory=list)
    vout: list[TxOut] = field(default_factory=list)
    witness: list[list[bytes]] = field(default_factory=list)  # one stack per input; empty = no witness

    def serialize(self, with_witness: bool = True) -> bytes:
        has_w = with_witness and any(self.witness)
        out = struct.pack("<I", self.version & 0xFFFFFFFF)
        if has_w:
            out += b"\x00\x01"
        out += varint(len(self.vin))
        for i in self.vin:
            out += bytes.fromhex(i.txid)[::-1] + struct.pack("<I", i.vout) + ser_string(i.script_sig)
            out += struct.pack("<I", i.sequence)
        out += varint(len(self.vout))
        for o in self.vout:
            out += ser_output(o)
        if has_w:
            for k in range(len(self.vin)):
                stack = self.witness[k] if k < len(self.witness) else []
                out += varint(len(stack)) + b"".join(ser_string(item) for item in stack)
        return out + struct.pack("<I", self.locktime)

    def txid(self) -> str:
        return sha256(sha256(self.serialize(with_witness=False)))[::-1].hex()

    def wtxid(self) -> str:
        return sha256(sha256(self.serialize()))[::-1].hex()

    def hex(self) -> str:
        return self.serialize().hex()


class _Reader:
    def __init__(self, data: bytes):
        self.d, self.p = data, 0

    def take(self, n: int) -> bytes:
        b = self.d[self.p:self.p + n]
        if len(b) != n:
            raise ValueError("truncated transaction")
        self.p += n
        return b

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def varint(self) -> int:
        b = self.take(1)[0]
        if b < 0xFD:
            return b
        if b == 0xFD:
            return struct.unpack("<H", self.take(2))[0]
        if b == 0xFE:
            return struct.unpack("<I", self.take(4))[0]
        return struct.unpack("<Q", self.take(8))[0]

    def string(self) -> bytes:
        return self.take(self.varint())


def parse_output(raw: bytes | str) -> TxOut:
    r = _Reader(bytes.fromhex(raw) if isinstance(raw, str) else raw)
    value = struct.unpack("<q", r.take(8))[0]
    out = TxOut(value, r.string())
    if r.p != len(r.d):
        raise ValueError("trailing bytes after output")
    return out


def parse_tx(raw: bytes | str) -> Tx:
    r = _Reader(bytes.fromhex(raw) if isinstance(raw, str) else raw)
    tx = Tx(version=r.u32())
    n = r.varint()
    segwit = False
    if n == 0 and r.d[r.p] == 1:  # marker 00, flag 01
        r.take(1)
        segwit = True
        n = r.varint()
    for _ in range(n):
        txid = r.take(32)[::-1].hex()
        vout = r.u32()
        script_sig = r.string()
        tx.vin.append(TxIn(txid, vout, script_sig, r.u32()))
    for _ in range(r.varint()):
        value = struct.unpack("<q", r.take(8))[0]
        tx.vout.append(TxOut(value, r.string()))
    if segwit:
        for _ in range(n):
            tx.witness.append([r.string() for _ in range(r.varint())])
    tx.locktime = r.u32()
    if r.p != len(r.d):
        raise ValueError("trailing bytes after transaction")
    return tx
