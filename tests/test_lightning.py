"""The swap lock and per-payment menus, with no node: scripts, signatures, and the prover's lock check."""
from __future__ import annotations

import contextlib
import hashlib
import io
import threading
import unittest
from unittest import mock

from secondstar import htlc, secp, vault
from secondstar.prove import prove

COLD = bytes([0, 20]) + b"\x22" * 20
OWNER, PROVIDER, HOOK = 0x0C01D, 0x9A0, 0xBAD


def swap_vault(refund_key=OWNER, periods=3):
    locks = [htlc.lock(htlc.preimage_pair(b"seed", k)[1], secp.pubkey(PROVIDER), secp.pubkey(refund_key), 144)
             for k in range(periods)]
    v = vault.build(1_000_000, 100_000, periods, 3, [], COLD, secp.pubkey(OWNER), "ctv",
                    menus=[[lk.script_pubkey] for lk in locks])
    claims = dict(vault.claims(v), swap_locks=htlc.describe(locks))
    return v, locks, claims


class Lock(unittest.TestCase):
    def test_script_numbers_are_minimal(self):
        self.assertEqual(htlc.script_num(1), b"\x51")
        self.assertEqual(htlc.script_num(16), b"\x60")
        self.assertEqual(htlc.script_num(17), b"\x01\x11")
        self.assertEqual(htlc.script_num(144), b"\x02\x90\x00")

    def test_claim_needs_the_preimage_and_the_provider_key(self):
        p, h = htlc.preimage_pair(b"seed", 0)
        self.assertEqual(hashlib.sha256(p).digest(), h)
        lk = htlc.lock(h, secp.pubkey(PROVIDER), secp.pubkey(OWNER), 144)
        tx = htlc.claim_tx(lk, ("ab" * 32, 0), 100_000, COLD, 500, PROVIDER, p)
        digest = secp.sighash_script_path(tx, 0, [(100_000, lk.script_pubkey)], lk.leaf_hash[lk.claim])
        self.assertTrue(secp.verify(digest, secp.pubkey(PROVIDER), tx.witness[0][0]))
        self.assertEqual(tx.witness[0][1], p)
        self.assertEqual(tx.witness[0][2], lk.claim)

    def test_refund_waits_and_needs_the_owner_key(self):
        lk = htlc.lock(htlc.preimage_pair(b"seed", 0)[1], secp.pubkey(PROVIDER), secp.pubkey(OWNER), 144)
        tx = htlc.refund_tx(lk, ("ab" * 32, 0), 100_000, COLD, 500, OWNER)
        self.assertEqual(tx.vin[0].sequence, 144)
        digest = secp.sighash_script_path(tx, 0, [(100_000, lk.script_pubkey)], lk.leaf_hash[lk.refund])
        self.assertTrue(secp.verify(digest, secp.pubkey(OWNER), tx.witness[0][0]))


class ProverOnLocks(unittest.TestCase):
    def test_swap_vault_proves_with_its_locks(self):
        v, locks, claims = swap_vault()
        cert = prove(vault.describe(v), claims)
        self.assertEqual(cert["verdict"], "PROVED", cert["failures"])
        self.assertEqual(cert["most_paid_after_k_steps"], {"1": 100_000, "2": 200_000, "3": 300_000})
        self.assertIn("swap lock", cert["statement"])
        for k in range(3):   # payment k goes to lock k
            st = v.states[(k, k)]
            self.assertEqual(st.choices["pay:0"].template.vout[0].script_pubkey, locks[k].script_pubkey)

    def test_lock_refunding_to_someone_else_is_refuted(self):
        v, _, claims = swap_vault(refund_key=HOOK)
        cert = prove(vault.describe(v), dict(claims))
        self.assertEqual(cert["verdict"], "REFUTED")
        self.assertTrue(any("not the owner's" in f for f in cert["failures"]), cert["failures"])

    def test_claimed_locks_must_be_the_menu(self):
        v, locks, claims = swap_vault()
        wrong = htlc.describe([htlc.lock(b"\x01" * 32, secp.pubkey(PROVIDER), secp.pubkey(OWNER), 144)] + locks[1:])
        cert = prove(vault.describe(v), dict(claims, swap_locks=wrong))
        self.assertEqual(cert["verdict"], "REFUTED")
        self.assertTrue(any("not exactly the listed swap locks" in f for f in cert["failures"]), cert["failures"])

    def refuted(self, v, locks, needle):
        cert = prove(vault.describe(v), dict(vault.claims(v), swap_locks=htlc.describe(locks)))
        self.assertEqual(cert["verdict"], "REFUTED")
        self.assertTrue(any(needle in f for f in cert["failures"]), cert["failures"])

    def test_one_lock_paid_every_period_is_refuted(self):
        """Red-team counterexample A: one secret would unlock every tranche."""
        lk = htlc.lock(htlc.preimage_pair(b"seed", 0)[1], secp.pubkey(PROVIDER), secp.pubkey(OWNER), 144)
        v = vault.build(1_000_000, 100_000, 3, 3, [lk.script_pubkey], COLD, secp.pubkey(OWNER), "ctv")
        self.refuted(v, [lk], "paid twice on one path")

    def test_fresh_addresses_sharing_one_hash_are_refuted(self):
        """Red-team counterexample B: three different addresses, one payment hash."""
        h = htlc.preimage_pair(b"seed", 0)[1]
        locks = [htlc.lock(h, secp.pubkey(PROVIDER), secp.pubkey(OWNER), 144 + k) for k in range(3)]
        v = vault.build(1_000_000, 100_000, 3, 3, [], COLD, secp.pubkey(OWNER), "ctv",
                        menus=[[lk.script_pubkey] for lk in locks])
        self.refuted(v, locks, "shares its payment hash")

    def test_unusable_claim_path_is_refuted(self):
        """Red-team counterexample C: a provider key that is not a curve point, and an all-zero hash."""
        bad = htlc.lock(bytes(32), (5).to_bytes(32, "big"), secp.pubkey(OWNER), 1)
        v = vault.build(1_000_000, 100_000, 1, 3, [bad.script_pubkey], COLD, secp.pubkey(OWNER), "ctv")
        self.refuted(v, [bad], "can never be used")

    def test_swap_statement_says_fund_once(self):
        v, _, claims = swap_vault()
        cert = prove(vault.describe(v), claims)
        self.assertIn("Fund the vault once", cert["statement"])
        self.assertNotIn("separate allowance", cert["statement"])

    def test_menus_must_be_distinct_and_complete(self):
        lk = htlc.lock(b"\x02" * 32, secp.pubkey(PROVIDER), secp.pubkey(OWNER), 144)
        with self.assertRaises(ValueError):
            vault.build(1_000_000, 100_000, 3, 3, [], COLD, secp.pubkey(OWNER), menus=[[lk.script_pubkey]] * 3)
        with self.assertRaises(ValueError):
            vault.build(1_000_000, 100_000, 3, 3, [], COLD, secp.pubkey(OWNER), menus=[[lk.script_pubkey]])


class ProviderGate(unittest.TestCase):
    def test_too_late_expiry_calls_the_swap_off_before_settling(self):
        """Referee, second pass: the real-expiry check must stop the swap, not only report it. A stand-in provider whose
        HTLC came out later than the cap allowed: the invoice is canceled and nothing settles."""
        from secondstar import lightning_run as lr
        lock = htlc.lock(htlc.preimage_pair(b"seed", 0)[1], secp.pubkey(PROVIDER), secp.pubkey(OWNER), 144)

        class Provider:
            def cli(self, *args):
                if args[0] == "decodepayreq":
                    return {"payment_hash": lock.payment_hash.hex(), "num_satoshis": str(lr.TRANCHE - lr.SWAP_FEE),
                            "cltv_expiry": "40"}
                if args[0] == "listchannels":
                    return {"channels": [{"pending_htlcs": [{"hash_lock": lock.payment_hash.hex(), "incoming": False,
                                                             "expiration_height": "1300"}]}]}
                raise AssertionError(args)

        class Chain:
            def call(self, method, *args):
                return 1000                                  # getblockcount: the tip, and the lock's height

        run = object.__new__(lr.Run)
        run.ln, run.chain, run.fails, run.events = {"provider": Provider()}, Chain(), [], []
        caps, calls, called_off = [], [], threading.Event()

        def fake_pay(wallet, payment_request, cltv_limit=None):
            caps.append(cltv_limit)
            called_off.wait(10)
            return ""

        def cancel():
            calls.append("cancel")
            called_off.set()

        with mock.patch.object(lr, "pay", fake_pay), contextlib.redirect_stdout(io.StringIO()):
            out = run.provider_pays_and_claims("lnbcrt-stand-in", lock, ("ab" * 32, 0), 1000,
                                               settle=lambda: calls.append("settle"), cancel=cancel)
        self.assertIsNone(out)
        self.assertEqual(calls, ["cancel"])
        self.assertEqual(caps, [1000 + 144 - 12 - 1 - 1000])     # the cap LND was given: 131 blocks
        self.assertTrue(any("real expiry" in f for f in run.fails), run.fails)


if __name__ == "__main__":
    unittest.main()
