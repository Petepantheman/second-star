"""Second Star: a Bitcoin allowance an AI agent can spend from without ever holding a key.

Each period the coins sit in a Taproot output with no key path (the BIP-341 unspendable internal key). Its leaves:

  pay:i   pay exactly `tranche` sats to menu address i, the rest into the next period's vault
  skip    pay nobody, move everything into the next period's vault
  cold    the owner's key, which can sweep everything at any time

Every covenant leaf commits to one exact transaction, either with OP_CHECKTEMPLATEVERIFY (BIP-119) or with
OP_TEMPLATEHASH (BIP-446). Every covenant transaction carries a relative timelock of `delay` blocks (BIP-68), so
at most one period can pass per `delay` blocks. After the last period, whatever is left goes back to the owner.

Covenant transactions are version 3 and pay no fee themselves. Their last output is a 0-value pay-to-anchor
(OP_1 <4e73>), and whoever broadcasts attaches a child that spends the anchor and pays the miner from its own
coins. The anchor is inside the committed template, so the child cannot change who gets paid or how much.

The states are built from the last period backwards, because each template commits the address of the next one.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import secp
from .hashes import ctv_hash, template_hash
from .tx import Tx, TxIn, TxOut

DUST = 546
ANCHOR = bytes.fromhex("51024e73")          # pay-to-anchor: OP_1 PUSH2 0x4e73
OP_CTV, OP_TEMPLATEHASH, OP_EQUAL, OP_CHECKSIG = 0xB3, 0xCE, 0x87, 0xAC
OPCODES = ("ctv", "templatehash")


def covenant_leaf(opcode: str, template: Tx) -> bytes:
    """The whole leaf script. CTV: <hash> OP_CHECKTEMPLATEVERIFY. TEMPLATEHASH: <hash> OP_TEMPLATEHASH OP_EQUAL."""
    if opcode == "ctv":
        return bytes([0x20]) + ctv_hash(template, 0) + bytes([OP_CTV])
    if opcode == "templatehash":
        return bytes([0x20]) + template_hash(template, 0) + bytes([OP_TEMPLATEHASH, OP_EQUAL])
    raise ValueError(f"opcode must be one of {OPCODES}")


def cold_leaf(cold_x: bytes) -> bytes:
    return bytes([0x20]) + cold_x + bytes([OP_CHECKSIG])


@dataclass
class Choice:
    name: str
    template: Tx
    script: bytes
    control: bytes

    def witness(self) -> list[bytes]:
        return [self.script, self.control]


@dataclass
class State:
    period: int
    paid: int
    value: int
    script_pubkey: bytes
    choices: dict[str, Choice]
    scripts: list[bytes]      # every leaf, in tree order
    shape: object             # the tree as nested pairs of leaf indexes
    cold_script: bytes
    control_cold: bytes
    leaf_cold: bytes


@dataclass
class Vault:
    opcode: str
    funding: int
    tranche: int
    periods: int
    delay: int
    menu: list[bytes]
    cold_spk: bytes
    cold_x: bytes
    states: dict[tuple[int, int], State]

    @property
    def root(self) -> State:
        return self.states[(0, 0)]


def value_at(funding: int, tranche: int, paid: int) -> int:
    return funding - paid * tranche


def build(funding: int, tranche: int, periods: int, delay: int, menu: list[bytes], cold_spk: bytes,
          cold_x: bytes, opcode: str = "ctv") -> Vault:
    """Every state the coins can ever be in, keyed by (period, payments made so far)."""
    if opcode not in OPCODES:
        raise ValueError(f"opcode must be one of {OPCODES}")
    if len(cold_x) != 32:
        raise ValueError("cold key must be a 32-byte x-only public key")
    if not (1 <= delay <= 0xFFFF):
        raise ValueError("delay must be 1..65535 blocks")
    if periods < 1 or tranche < DUST or not menu:
        raise ValueError("periods >= 1, a non-empty menu, tranche above dust")
    if len(set(menu)) != len(menu):
        raise ValueError("menu addresses must be distinct")
    if cold_spk in menu:
        raise ValueError("the cold address is the owner's exit, not a menu payment")
    if value_at(funding, tranche, periods) < DUST:
        raise ValueError(f"{funding} sats cannot pay {periods} tranches of {tranche} and still return dust")
    cs = cold_leaf(cold_x)
    states: dict[tuple[int, int], State] = {}
    for period in range(periods - 1, -1, -1):
        for paid in range(period + 1):
            value = value_at(funding, tranche, paid)
            last = period + 1 == periods
            made: list[tuple[str, Tx]] = []
            for i, spk in enumerate(menu):
                nxt = cold_spk if last else states[(period + 1, paid + 1)].script_pubkey
                made.append((f"pay:{i}", Tx(3, 0, [TxIn(sequence=delay)], [
                    TxOut(tranche, spk), TxOut(value - tranche, nxt), TxOut(0, ANCHOR)])))
            nxt = cold_spk if last else states[(period + 1, paid)].script_pubkey
            made.append(("skip", Tx(3, 0, [TxIn(sequence=delay)], [TxOut(value, nxt), TxOut(0, ANCHOR)])))
            leaves = [(name, tx, covenant_leaf(opcode, tx)) for name, tx in made]
            scripts = [script for _, _, script in leaves] + [cs]
            tree = secp.script_tree(scripts)
            choices = {name: Choice(name, tx, script, tree["control"][script]) for name, tx, script in leaves}
            states[(period, paid)] = State(period, paid, value, tree["script_pubkey"], choices, scripts,
                                           tree["shape"], cs, tree["control"][cs], tree["leaf_hash"][cs])
    return Vault(opcode, funding, tranche, periods, delay, list(menu), cold_spk, cold_x, states)


def spend(state: State, name: str, prev_txid: str, prev_vout: int, outputs=None, sequence: int | None = None,
          version: int | None = None) -> Tx:
    """The named leaf, pointed at a real coin. `outputs`, `sequence` and `version` exist only so an attacker can
    try something the template does not allow."""
    choice = state.choices[name]
    t = choice.template
    return Tx(t.version if version is None else version, t.locktime,
              [TxIn(prev_txid, prev_vout, b"", t.vin[0].sequence if sequence is None else sequence)],
              list(t.vout) if outputs is None else outputs, [choice.witness()])


def sweep(state: State, prev_txid: str, prev_vout: int, to_spk: bytes, fee: int, secret: int | None,
          sig_override: bytes | None = None) -> Tx:
    """Everything in this state to `to_spk`, signed on the cold leaf. No delay. With `secret` None and
    `sig_override` set, this builds a forged attempt."""
    tx = Tx(2, 0, [TxIn(prev_txid, prev_vout, b"", 0xFFFFFFFF)], [TxOut(state.value - fee, to_spk)])
    if sig_override is None:
        digest = secp.sighash_script_path(tx, 0, [(state.value, state.script_pubkey)], state.leaf_cold)
        sig = secp.sign(digest, secret)
    else:
        sig = sig_override
    tx.witness = [[sig, state.cold_script, state.control_cold]]
    return tx


def describe(v: Vault) -> dict:
    """Everything the prover needs, as plain hex: every reachable vault, every leaf, the tree shape, and the
    committed template behind each covenant leaf. The prover recomputes all of it from these bytes."""
    out = {"format": "second-star/1", "opcode": v.opcode, "root": v.root.script_pubkey.hex(), "vaults": {}}
    for st in v.states.values():
        templates = {}
        for choice in st.choices.values():
            templates[str(st.scripts.index(choice.script))] = choice.template.hex()
        out["vaults"][st.script_pubkey.hex()] = {
            "internal_key": secp.NUMS_X.to_bytes(32, "big").hex(),
            "leaves": [s.hex() for s in st.scripts],
            "shape": st.shape,
            "templates": templates,
        }
    return out


def claims(v: Vault) -> dict:
    """What the owner says the vault does. The prover checks the bytes against these numbers."""
    return {"funding": v.funding, "tranche": v.tranche, "periods": v.periods, "delay": v.delay,
            "menu": [m.hex() for m in v.menu], "cold": v.cold_spk.hex(), "cold_key": v.cold_x.hex()}
