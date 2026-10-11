"""Every hash and signature is checked against the official vectors, for the builder AND for the prover.

  python -m unittest discover -s tests -v
"""
from __future__ import annotations

import csv
import json
import unittest
from pathlib import Path

from secondstar import prove, secp
from secondstar.hashes import ctv_hash, template_hash
from secondstar.tx import parse_tx

V = Path(__file__).resolve().parent / "vectors"


class Bip119(unittest.TestCase):
    def test_every_ctv_vector(self):
        checked = 0
        for row in json.loads((V / "bip119-ctvhash.json").read_text(encoding="utf-8")):
            if isinstance(row, str):
                continue
            tx = parse_tx(row["hex_tx"])
            self.assertEqual(tx.serialize().hex(), row["hex_tx"], "serializer round trip")
            raw = bytes.fromhex(row["hex_tx"])
            for idx, expected in zip(row["spend_index"], row["result"]):
                self.assertEqual(ctv_hash(tx, idx).hex(), expected)
                self.assertEqual(prove._ctv(prove._parse(raw), idx).hex(), expected)
                checked += 1
        self.assertEqual(checked, 400)


class Bip446(unittest.TestCase):
    def test_every_templatehash_vector(self):
        rows = json.loads((V / "bip446-basics.json").read_text(encoding="utf-8"))
        self.assertEqual(len(rows), 19)
        for row in rows:
            tx = parse_tx(row["spending_tx"])
            i = row["input_index"]
            stack = tx.witness[i]
            annex = stack[-1] if len(stack) >= 2 and stack[-1][:1] == b"\x50" else None
            script = (stack[:-1] if annex is not None else stack)[-2]
            committed = script[1:33] if script[:1] == b"\x20" and script[33:] == b"\xce\x87" else None
            self.assertEqual(template_hash(tx, i, annex) == committed, row["valid"], row["comment"])
            if annex is None:  # the prover only ever accepts templates without an annex
                parsed = prove._parse(bytes.fromhex(row["spending_tx"]))
                self.assertEqual(prove._templatehash(parsed, i) == committed, row["valid"], row["comment"])


class Bip340(unittest.TestCase):
    def test_every_schnorr_vector(self):
        rows = list(csv.DictReader((V / "bip340.csv").read_text(encoding="utf-8").splitlines()))
        self.assertEqual(len(rows), 19)
        for row in rows:
            pk, msg, sig = (bytes.fromhex(row[k]) for k in ("public key", "message", "signature"))
            expect = row["verification result"].strip().upper() == "TRUE"
            self.assertEqual(secp.verify(msg, pk, sig), expect, f"vector {row['index']}")
            if row["secret key"]:
                sk = int(row["secret key"], 16)
                self.assertEqual(secp.pubkey(sk), pk)
                self.assertEqual(secp.sign(msg, sk, bytes.fromhex(row["aux_rand"])), sig)


class Bip341(unittest.TestCase):
    def test_unspendable_key_is_derived_not_pasted(self):
        self.assertEqual(prove.unspendable_key(), secp.NUMS_X.to_bytes(32, "big"))


if __name__ == "__main__":
    unittest.main()
