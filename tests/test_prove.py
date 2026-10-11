"""The prover must say PROVED for honest vaults and REFUTED for every broken one.

Each negative control rebuilds the root vault with one flaw and a correct address, so the prover has to find the
flaw itself rather than trip over a mismatched address.
"""
from __future__ import annotations

import copy
import unittest

from secondstar import secp, vault
from secondstar.prove import prove
from secondstar.tx import Tx, TxIn, TxOut, parse_tx

MENU = [bytes([0, 20]) + b"\x11" * 20, bytes([0, 20]) + b"\x33" * 20]
COLD = bytes([0, 20]) + b"\x22" * 20
THIEF = bytes([0, 20]) + b"\x99" * 20
COLD_X = secp.pubkey(0xC01D)


def honest(opcode="ctv", periods=3):
    v = vault.build(1_000_000, 100_000, periods, 3, MENU, COLD, COLD_X, opcode)
    return v, vault.describe(v), vault.claims(v)


def forge_root(desc, opcode, scripts, templates, internal_x=None):
    """Replace the root vault with these leaves (and templates), re-deriving its address honestly."""
    tree = secp.script_tree(scripts, internal_x)
    new = copy.deepcopy(desc)
    old_root = new["root"]
    entry = new["vaults"].pop(old_root)
    entry["leaves"] = [s.hex() for s in scripts]
    entry["shape"] = tree["shape"]
    entry["templates"] = {str(i): t.hex() for i, t in templates.items()}
    if internal_x is not None:
        entry["internal_key"] = internal_x.hex()
    new["root"] = tree["script_pubkey"].hex()
    new["vaults"][new["root"]] = entry
    return new


def root_parts(v):
    st = v.root
    templates = {st.scripts.index(c.script): copy.deepcopy(c.template) for c in st.choices.values()}
    return list(st.scripts), templates


def with_template(v, opcode, leaf_index, tx):
    scripts, templates = root_parts(v)
    scripts[leaf_index] = vault.covenant_leaf(opcode, tx)
    templates[leaf_index] = tx
    return scripts, templates


class Honest(unittest.TestCase):
    def test_both_opcodes_prove(self):
        for opcode in vault.OPCODES:
            _, desc, claims = honest(opcode)
            cert = prove(desc, claims)
            self.assertEqual(cert["verdict"], "PROVED", cert["failures"])
            self.assertEqual(cert["vaults"], 6)
            self.assertEqual(cert["most_paid_after_k_steps"], {"1": 100_000, "2": 200_000, "3": 300_000})

    def test_many_shapes_prove(self):
        for periods in (1, 2, 5):
            for n in (1, 3):
                menu = [bytes([0, 20]) + bytes([0x40 + i]) * 20 for i in range(n)]
                v = vault.build(5_000_000, 50_000, periods, 6, menu, COLD, COLD_X, "templatehash")
                cert = prove(vault.describe(v), vault.claims(v))
                self.assertEqual(cert["verdict"], "PROVED", cert["failures"])
                self.assertEqual(cert["longest_path"], periods)


class Refutes:
    def refuted(self, desc, claims, needle):
        cert = prove(desc, claims)
        self.assertEqual(cert["verdict"], "REFUTED")
        self.assertTrue(any(needle in f for f in cert["failures"]), cert["failures"])


class Broken(Refutes, unittest.TestCase):

    def test_hidden_back_door_leaf_is_found(self):
        v, desc, claims = honest()
        scripts, templates = root_parts(v)
        thief_leaf = bytes([0x20]) + secp.pubkey(0xBAD) + bytes([0xAC])
        self.refuted(forge_root(desc, "ctv", scripts + [thief_leaf], templates), claims, "foreign-key")

    def test_unlisted_leaf_cannot_hide(self):
        v, desc, claims = honest()
        scripts, templates = root_parts(v)
        forged = forge_root(desc, "ctv", scripts + [b"\x51"], templates)
        entry = forged["vaults"][forged["root"]]
        entry["leaves"] = entry["leaves"][:-1]          # list every leaf except the back door
        entry["shape"] = secp.script_tree(scripts)["shape"]
        self.refuted(forged, claims, "do not produce this address")

    def test_anyone_can_spend_leaf_is_found(self):
        v, desc, claims = honest()
        scripts, templates = root_parts(v)
        self.refuted(forge_root(desc, "ctv", scripts + [b"\x51"], templates), claims, "unknown")

    def test_key_path_is_found(self):
        v, desc, claims = honest()
        scripts, templates = root_parts(v)
        self.refuted(forge_root(desc, "ctv", scripts, templates, secp.pubkey(0xBAD)), claims, "internal key")

    def test_payment_to_a_thief_is_found(self):
        for opcode in vault.OPCODES:
            v, desc, claims = honest(opcode)
            t = copy.deepcopy(v.root.choices["pay:0"].template)
            t.vout[0] = TxOut(100_000, THIEF)
            scripts, templates = with_template(v, opcode, 0, t)
            self.refuted(forge_root(desc, opcode, scripts, templates), claims, "not on the menu")

    def test_double_tranche_is_found(self):
        v, desc, claims = honest()
        t = copy.deepcopy(v.root.choices["pay:0"].template)
        t.vout[0] = TxOut(200_000, MENU[0])
        t.vout[1] = TxOut(800_000, t.vout[1].script_pubkey)
        scripts, templates = with_template(v, "ctv", 0, t)
        self.refuted(forge_root(desc, "ctv", scripts, templates), claims, "more than the tranche")

    def test_missing_timelock_is_found(self):
        v, desc, claims = honest()
        t = copy.deepcopy(v.root.choices["pay:0"].template)
        t.vin[0] = TxIn(sequence=0xFFFFFFFF)
        scripts, templates = with_template(v, "ctv", 0, t)
        self.refuted(forge_root(desc, "ctv", scripts, templates), claims, "relative timelock")

    def test_split_into_two_vaults_is_found(self):
        v, desc, claims = honest()
        t = copy.deepcopy(v.root.choices["skip"].template)
        nxt = t.vout[0].script_pubkey
        t.vout = [TxOut(500_000, nxt), TxOut(500_000, nxt), TxOut(0, vault.ANCHOR)]
        scripts, templates = with_template(v, "ctv", len(MENU), t)
        self.refuted(forge_root(desc, "ctv", scripts, templates), claims, "splits")

    def test_value_leak_to_fees_is_found(self):
        v, desc, claims = honest()
        t = copy.deepcopy(v.root.choices["pay:0"].template)
        t.vout[1] = TxOut(t.vout[1].value - 50_000, t.vout[1].script_pubkey)
        scripts, templates = with_template(v, "ctv", 0, t)
        self.refuted(forge_root(desc, "ctv", scripts, templates), claims, "!= vault value")

    def test_funded_anchor_is_found(self):
        v, desc, claims = honest()
        t = copy.deepcopy(v.root.choices["pay:0"].template)
        t.vout[1] = TxOut(t.vout[1].value - 1_000, t.vout[1].script_pubkey)
        t.vout[2] = TxOut(1_000, vault.ANCHOR)
        scripts, templates = with_template(v, "ctv", 0, t)
        self.refuted(forge_root(desc, "ctv", scripts, templates), claims, "anchor carries")

    def test_template_that_does_not_match_its_hash_is_found(self):
        v, desc, claims = honest()
        desc = copy.deepcopy(desc)
        entry = desc["vaults"][desc["root"]]
        honest_pay = parse_tx(entry["templates"]["0"])
        honest_pay.vout[0] = TxOut(100_000, MENU[1])        # claim leaf 0 pays menu 1
        entry["templates"]["0"] = honest_pay.hex()
        self.refuted(desc, claims, "hash is not the hash")

    def test_wrong_claims_are_found(self):
        _, desc, claims = honest()
        lower = dict(claims, tranche=99_999)
        self.refuted(desc, lower, "more than the tranche")
        faster = dict(claims, delay=2)
        self.refuted(desc, faster, "relative timelock")

    def test_mixed_opcodes_are_found(self):
        v, desc, claims = honest("ctv")
        t = copy.deepcopy(v.root.choices["pay:0"].template)
        scripts, templates = with_template(v, "templatehash", 0, t)
        self.refuted(forge_root(desc, "ctv", scripts, templates), claims, "templatehash leaf in a ctv vault")

    def test_extra_input_template_is_found(self):
        v, desc, claims = honest()
        t = copy.deepcopy(v.root.choices["pay:0"].template)
        t.vin.append(TxIn(sequence=3))
        scripts, templates = with_template(v, "ctv", 0, t)
        self.refuted(forge_root(desc, "ctv", scripts, templates), claims, "exactly one input")


class BrokenMore(Refutes, unittest.TestCase):
    """Controls added after review: timelock encodings, versions, scriptSig, amounts, claims, depth, values."""

    def broken_pay(self, mutate, needle, opcode="ctv"):
        v, desc, claims = honest(opcode)
        t = copy.deepcopy(v.root.choices["pay:0"].template)
        mutate(t)
        scripts, templates = with_template(v, opcode, 0, t)
        self.refuted(forge_root(desc, opcode, scripts, templates), claims, needle)

    def test_version_1_has_no_relative_timelock(self):
        self.broken_pay(lambda t: setattr(t, "version", 1), "relative timelock")

    def test_time_based_lock_is_not_blocks(self):
        self.broken_pay(lambda t: setattr(t.vin[0], "sequence", (1 << 22) | 3), "relative timelock")

    def test_disabled_lock_is_found(self):
        self.broken_pay(lambda t: setattr(t.vin[0], "sequence", (1 << 31) | 3), "relative timelock")

    def test_absolute_locktime_is_found(self):
        self.broken_pay(lambda t: setattr(t, "locktime", 0xFFFFFFFE), "nLockTime")

    def test_script_sig_is_found(self):
        self.broken_pay(lambda t: setattr(t.vin[0], "script_sig", b"Q"), "empty scriptSig")

    def test_negative_output_is_found(self):
        def mutate(t):
            t.vout[0] = TxOut(300_000, MENU[0])
            t.vout.insert(1, TxOut(-200_000, MENU[1]))
        self.broken_pay(mutate, "negative")

    def test_vault_reached_with_two_amounts_is_found(self):
        v, desc, claims = honest()
        t = copy.deepcopy(v.root.choices["skip"].template)
        t.vout[0] = TxOut(1_000_000, v.states[(1, 1)].script_pubkey)   # (1,1) is also reached holding 900,000
        scripts, templates = with_template(v, "ctv", len(MENU), t)
        self.refuted(forge_root(desc, "ctv", scripts, templates), claims, "two different amounts")

    def test_bad_claims_are_found(self):
        _, desc, claims = honest()
        for bad, needle in ((dict(claims, delay=0), "delay"), (dict(claims, tranche=float("nan")), "tranche"),
                            (dict(claims, periods=float("inf")), "periods"), (dict(claims, menu=[]), "menu"),
                            (dict(claims, cold_key="05" * 32), "cold_key")):
            self.refuted(desc, bad, needle)

    def test_malformed_template_is_refuted_not_crashed(self):
        _, desc, claims = honest()
        desc = copy.deepcopy(desc)
        desc["vaults"][desc["root"]]["templates"]["0"] = "0300"
        self.refuted(desc, claims, "does not parse")

    def test_owner_leaf_too_deep_is_found(self):
        v, desc, claims = honest()
        scripts, templates = root_parts(v)
        pay0 = scripts[0]
        leaves = [pay0] * 129 + [scripts[-1]]            # 130 leaves, a caterpillar: the owner leaf at depth 129
        shape = 0
        for i in range(1, 130):
            shape = [shape, i]
        hashes = [secp.leaf_hash(x) for x in leaves]

        def root(sh):
            return hashes[sh] if isinstance(sh, int) else secp.branch_hash(root(sh[0]), root(sh[1]))
        out_x, _ = secp.taproot_output(secp.NUMS_X.to_bytes(32, "big"), root(shape))
        new = copy.deepcopy(desc)
        entry = new["vaults"].pop(new["root"])
        entry["leaves"] = [x.hex() for x in leaves]
        entry["shape"] = shape
        entry["templates"] = {str(i): templates[0].hex() for i in range(129)}
        new["root"] = (bytes([0x51, 0x20]) + out_x).hex()
        new["vaults"][new["root"]] = entry
        self.refuted(new, claims, "depth")


class AttacksMissTheHash(unittest.TestCase):
    def test_every_scripted_attack_has_a_different_template_hash(self):
        from secondstar import hook
        from secondstar.hashes import ctv_hash, template_hash
        v, _, _ = honest()
        st = v.root
        committed = {ctv_hash(c.template, 0) for c in st.choices.values()}
        committed_th = {template_hash(c.template, 0) for c in st.choices.values()}
        for a in hook.scripted(st, MENU, THIEF, ("ab" * 32, 0), ("cd" * 32, 1)):
            if a.owner_path:
                continue
            self.assertNotIn(ctv_hash(a.tx, 0), committed, a.label)
            self.assertNotIn(template_hash(a.tx, 0), committed_th, a.label)


if __name__ == "__main__":
    unittest.main()
