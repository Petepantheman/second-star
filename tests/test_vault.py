"""The builder, with no node: schedule, anchor, menu-only outputs, and the owner's signature."""
from __future__ import annotations

import unittest

from secondstar import secp, vault
from secondstar.hashes import ctv_hash, template_hash
from secondstar.tx import TxOut

MENU = [bytes([0, 20]) + b"\x11" * 20, bytes([0, 20]) + b"\x33" * 20]
COLD = bytes([0, 20]) + b"\x22" * 20
SECRET = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF


class Schedule(unittest.TestCase):
    def test_states_values_and_anchor(self):
        for opcode in vault.OPCODES:
            v = vault.build(1_000_000, 100_000, 3, 3, MENU, COLD, secp.pubkey(SECRET), opcode)
            self.assertEqual(len(v.states), 6)
            self.assertEqual([v.states[k].value for k in ((0, 0), (1, 1), (2, 2))], [1_000_000, 900_000, 800_000])
            pay = v.root.choices["pay:0"].template
            self.assertEqual((pay.version, pay.vin[0].sequence), (3, 3))
            self.assertEqual([o.value for o in pay.vout], [100_000, 900_000, 0])
            self.assertEqual(pay.vout[-1].script_pubkey, vault.ANCHOR)
            skip = v.root.choices["skip"].template
            self.assertEqual(skip.vout[0].script_pubkey, v.states[(1, 0)].script_pubkey)
            last = v.states[(2, 2)].choices["pay:1"].template
            self.assertEqual(last.vout[1].script_pubkey, COLD)

    def test_any_change_breaks_the_hash(self):
        v = vault.build(1_000_000, 100_000, 3, 3, MENU, COLD, secp.pubkey(SECRET), "ctv")
        st = v.root
        thief = bytes([0, 20]) + b"\x99" * 20
        pay = st.choices["pay:0"].template
        for attempt in (
            vault.spend(st, "pay:0", "ab" * 32, 0, outputs=[TxOut(100_000, thief), pay.vout[1], pay.vout[2]]),
            vault.spend(st, "pay:0", "ab" * 32, 0, sequence=0xFFFFFFFF),
            vault.spend(st, "pay:0", "ab" * 32, 0, version=2),
        ):
            self.assertNotEqual(ctv_hash(attempt, 0), ctv_hash(pay, 0))
            self.assertNotEqual(template_hash(attempt, 0), template_hash(pay, 0))
        real = vault.spend(st, "pay:0", "cd" * 32, 7)  # the coin being spent is not committed
        self.assertEqual(ctv_hash(real, 0), ctv_hash(pay, 0))

    def test_bad_parameters_are_refused(self):
        x = secp.pubkey(SECRET)
        for args in ((1_000, 100_000, 3, 3), (1_000_000, 100_000, 3, 0), (1_000_000, 100, 3, 3)):
            with self.assertRaises(ValueError):
                vault.build(*args, MENU, COLD, x)
        with self.assertRaises(ValueError):
            vault.build(1_000_000, 100_000, 3, 3, MENU + [COLD], COLD, x)


class Owner(unittest.TestCase):
    def test_sweep_is_signed_by_the_cold_key_only(self):
        v = vault.build(1_000_000, 100_000, 3, 3, MENU, COLD, secp.pubkey(SECRET), "ctv")
        st = v.root
        tx = vault.sweep(st, "ab" * 32, 0, COLD, 500, SECRET)
        digest = secp.sighash_script_path(tx, 0, [(st.value, st.script_pubkey)], st.leaf_cold)
        self.assertTrue(secp.verify(digest, secp.pubkey(SECRET), tx.witness[0][0]))
        self.assertFalse(secp.verify(digest, secp.pubkey(SECRET + 1), tx.witness[0][0]))
        self.assertEqual(tx.vout[0].value, 999_500)


if __name__ == "__main__":
    unittest.main()
