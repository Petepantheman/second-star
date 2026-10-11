"""One command: start a private regtest node, build the vault, prove it, attack it, use it, and print what the node
said. Nothing touches a public network. The node and its folder are deleted at the end.

    python -m secondstar --bitcoind /path/to/inquisition/bitcoind
    python -m secondstar --opcode templatehash
    python -m secondstar --agent ollama:<model>     # let a local language model play the hijacked agent
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import hook, secp, vault
from .node import Node, RpcError, find_bitcoind
from .prove import prove
from .tx import Tx, TxIn, TxOut, parse_tx

FUNDING, TRANCHE, PERIODS, DELAY = 1_000_000, 100_000, 3, 3
CHILD_FEE, SWEEP_FEE = 10_000, 500
NEEDLE = {"ctv": "CHECKTEMPLATEVERIFY", "templatehash": "false/empty top stack element"}
WALLETS = ("miner", "menu0", "menu1", "owner", "hook")


def sats(btc) -> int:
    return int(round(float(btc) * 1e8))


def btc(n: int) -> str:
    return f"{n / 1e8:.8f}"


class Lab:
    def __init__(self, node: Node):
        self.n = node
        self.fails: list[str] = []
        self.events: list[dict] = []
        self.used: set[tuple[str, int]] = set()   # miner coins already promised to a fee child

    # ---- node helpers -----------------------------------------------------------------------------------------
    def addr(self, wallet: str) -> str:
        return self.n.call("getnewaddress", "", "bech32", wallet=wallet)

    def spk(self, address: str) -> bytes:
        return bytes.fromhex(self.n.call("validateaddress", address)["scriptPubKey"])

    def mine(self, blocks: int) -> None:
        self.n.call("generatetoaddress", blocks, self.addr("miner"))

    def balance(self, wallet: str) -> int:
        return sats(self.n.call("getbalance", wallet=wallet))

    def balances(self) -> dict[str, int]:
        return {w: self.balance(w) for w in ("menu0", "menu1", "owner", "hook")}

    def fund(self, script_pubkey: bytes) -> tuple[str, int]:
        address = self.n.call("decodescript", script_pubkey.hex())["address"]
        txid = self.n.call("sendtoaddress", address, btc(FUNDING), wallet="miner")
        self.mine(1)
        raw = self.n.call("getrawtransaction", txid, True)
        return txid, next(o["n"] for o in raw["vout"] if o["scriptPubKey"].get("address") == address)

    def fee_child(self, parent: Tx) -> Tx:
        """Spend the parent's 0-value anchor together with one of the miner's coins and pay the fee."""
        anchor = len(parent.vout) - 1
        utxo = next(u for u in self.n.call("listunspent", 101, wallet="miner")
                    if sats(u["amount"]) > 2 * CHILD_FEE and (u["txid"], u["vout"]) not in self.used)
        self.used.add((utxo["txid"], utxo["vout"]))
        child = Tx(3, 0, [TxIn(parent.txid(), anchor), TxIn(utxo["txid"], utxo["vout"])],
                   [TxOut(sats(utxo["amount"]) - CHILD_FEE, self.spk(self.addr("miner")))])
        prevs = [{"txid": parent.txid(), "vout": anchor, "scriptPubKey": vault.ANCHOR.hex(), "amount": 0},
                 {"txid": utxo["txid"], "vout": utxo["vout"], "scriptPubKey": utxo["scriptPubKey"],
                  "amount": utxo["amount"]}]
        signed = self.n.call("signrawtransactionwithwallet", child.hex(), prevs, wallet="miner")
        out = parse_tx(signed["hex"])
        if len(out.witness) < 2 or not out.witness[1]:
            raise SystemExit("the miner wallet did not sign the fee child")
        out.witness[0] = []  # the anchor is spent with an empty witness
        return out

    def submit(self, parent: Tx) -> tuple[bool, str]:
        """Parent plus fee child, as one package, the way it would reach a real mempool."""
        try:
            res = self.n.call("submitpackage", [parent.hex(), self.fee_child(parent).hex()])
        except RpcError as err:
            return False, err.message
        ok = res.get("package_msg") == "success"
        mine = (res.get("tx-results") or {}).get(parent.wtxid(), {})
        return ok, "accepted" if ok else str(mine.get("error") or res.get("package_msg"))

    def test_alone(self, tx: Tx) -> tuple[bool, str]:
        res = self.n.call("testmempoolaccept", [tx.hex()])[0]
        return bool(res.get("allowed")), res.get("reject-reason", "") + " " + res.get("reject-details", "")

    def as_miner(self, tx: Tx) -> tuple[bool, str]:
        """Ask the node to put this transaction straight into a block, skipping every mempool rule."""
        try:
            self.n.call("generateblock", self.addr("miner"), [tx.hex()])
            return True, "MINED"
        except RpcError as err:
            return False, err.message

    # ---- reporting ----------------------------------------------------------------------------------------------
    def refuse(self, who: str, says: str, tx: Tx, mempool_needle: str | None, block_needle: str,
               alone: bool = False) -> None:
        ok, reason = self.test_alone(tx) if alone else self.submit(tx)
        mok, mreason = self.as_miner(tx)
        good = (not ok and (mempool_needle is None or mempool_needle in reason)
                and not mok and block_needle in mreason)
        self.events.append({"who": who, "tried": says, "mempool": reason.strip(), "block": mreason.strip(),
                            "verdict": "REFUSED" if good else "UNEXPECTED"})
        print(f"  {who:<6}{says:<72} {'REFUSED' if good else 'UNEXPECTED'}")
        print(f"        mempool: {_short(reason)}")
        print(f"        miner  : {_short(mreason)}")
        if not good:
            self.fails.append(f"{who} {says}: mempool [{reason}] block [{mreason}]")

    def accept(self, who: str, says: str, tx: Tx) -> bool:
        ok, reason = self.submit(tx)
        if ok:
            self.mine(1)
            ok = self.n.call("getrawtransaction", tx.txid(), True).get("confirmations", 0) >= 1
        self.events.append({"who": who, "did": says, "txid": tx.txid(), "verdict": "CONFIRMED" if ok else reason})
        print(f"  {who:<6}{says:<72} {'CONFIRMED' if ok else 'REFUSED: ' + reason}")
        if not ok:
            self.fails.append(f"{who} {says}: {reason}")
        return ok

    def expect(self, what: str, got: int, want: int) -> None:
        if got != want:
            self.fails.append(f"{what}: {got:,} sats, expected {want:,}")


def _short(text: str, width: int = 96) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[:width - 3] + "..."


def run_opcode(lab: Lab, opcode: str, agent: str | None) -> dict:
    n = lab.n
    menu_addr = [lab.addr("menu0"), lab.addr("menu1")]
    menu = [lab.spk(a) for a in menu_addr]
    cold = lab.spk(lab.addr("owner"))
    hook_addr = lab.addr("hook")
    hook_spk = lab.spk(hook_addr)
    secret = int.from_bytes(os.urandom(32), "big") % secp.N or 1       # the owner's key lives only in memory
    v = vault.build(FUNDING, TRANCHE, PERIODS, DELAY, menu, cold, secp.pubkey(secret), opcode)
    cert = prove(vault.describe(v), vault.claims(v))
    print(f"\n== {opcode.upper()} vault: {FUNDING:,} sats, {TRANCHE:,} per period, {PERIODS} periods, "
          f"{DELAY}-block wait, 2 menu addresses")
    print(f"   prover: {cert['verdict']}  ({cert['vaults']} vaults, {cert['leaves']} leaves; most the menu can "
          f"receive after 1/2/3 steps: {', '.join(f'{p:,}' for p in cert['most_paid_after_k_steps'].values())})")
    if cert["verdict"] != "PROVED":
        lab.fails.append(f"{opcode} prover: {cert['failures']}")
        return {"opcode": opcode, "certificate": cert}
    start = lab.balances()
    needle = NEEDLE[opcode]

    print("   period 1")
    coin = lab.fund(v.root.script_pubkey)
    st = v.root
    lab.refuse("hook", "pay the menu before the wait is over", vault.spend(st, "pay:0", *coin),
               "non-BIP68-final", "bad-txns-nonfinal")
    attacks = hook.scripted(st, menu, hook_spk, coin)
    early = next(a for a in attacks if a.label == "no-wait")
    lab.refuse("hook", early.says, early.tx, needle, needle)
    lab.mine(DELAY)
    for a in attacks:
        if a.label == "no-wait":
            continue
        if a.owner_path:
            want = "Invalid Schnorr signature" if a.label == "forge" else "false/empty top stack element"
            lab.refuse("hook", a.says, a.tx, want, want, alone=True)
        else:
            lab.refuse("hook", a.says, a.tx, needle if a.label in ("drain", "redirect", "double") else None,
                       needle)
    pay = vault.spend(st, "pay:0", *coin)
    lab.accept("agent", f"pay menu 0 its {TRANCHE:,} sats", pay)

    print("   period 2")
    st = v.states[(1, 1)]
    coin = (pay.txid(), 1)
    lab.mine(DELAY)
    drain = hook.scripted(st, menu, hook_spk, coin)[0]
    lab.refuse("hook", drain.says + " (again)", drain.tx, needle, needle)
    skip = vault.spend(st, "skip", *coin)
    lab.accept("agent", "skip this period, pay nobody", skip)

    print("   period 3")
    st = v.states[(2, 1)]
    coin = (skip.txid(), 0)
    lab.mine(DELAY)
    last = vault.spend(st, "pay:1", *coin)
    lab.accept("agent", f"pay menu 1 its {TRANCHE:,} sats; the rest goes home to the owner", last)
    end = lab.balances()
    moved = {w: end[w] - start[w] for w in end}
    lab.expect(f"{opcode} menu 0", moved["menu0"], TRANCHE)
    lab.expect(f"{opcode} menu 1", moved["menu1"], TRANCHE)
    lab.expect(f"{opcode} owner", moved["owner"], FUNDING - 2 * TRANCHE)
    lab.expect(f"{opcode} hook", moved["hook"], 0)
    print(f"   result: menu 0 +{moved['menu0']:,} | menu 1 +{moved['menu1']:,} | owner +{moved['owner']:,} | "
          f"hook +{moved['hook']:,}")

    print("   the owner's exit (a second vault)")
    coin = lab.fund(v.root.script_pubkey)
    before = lab.balance("owner")
    sweep = vault.sweep(v.root, *coin, cold, SWEEP_FEE, secret)
    try:
        n.call("sendrawtransaction", sweep.hex())
        lab.mine(1)
        got = lab.balance("owner") - before
    except RpcError as err:
        got = 0
        lab.fails.append(f"{opcode} owner sweep refused: {err.message}")
    lab.expect(f"{opcode} owner sweep", got, FUNDING - SWEEP_FEE)
    print(f"  owner {'sweep everything home with one signature, no wait':<72} "
          f"{'CONFIRMED' if got == FUNDING - SWEEP_FEE else 'FAILED'} (+{got:,})")

    record = {"opcode": opcode, "certificate": cert, "moved": moved, "every_leaf": every_leaf(lab, v, secret, cold, hook_spk)}
    if agent:
        record["agent"] = run_agent(lab, v, menu_addr, hook_addr, agent)
    return record


def every_leaf(lab: Lab, v: vault.Vault, secret: int, cold: bytes, hook_spk: bytes) -> dict:
    """Spend every covenant leaf of every state on the node: the committed transaction must confirm, and the same
    transaction with its first output sent to Hook instead (same amounts, zero fee) must be refused by the mempool and
    by a miner-built block. Then the owner sweeps a coin out of every state."""
    needle = NEEDLE[v.opcode]
    honest = tampered = sweeps = 0
    total = sum(len(st.choices) for st in v.states.values())
    for (period, paid), st in sorted(v.states.items()):
        for name in sorted(st.choices):
            address = lab.n.call("decodescript", st.script_pubkey.hex())["address"]
            txid = lab.n.call("sendtoaddress", address, btc(st.value), wallet="miner")
            lab.mine(1)
            raw = lab.n.call("getrawtransaction", txid, True)
            coin = (txid, next(o["n"] for o in raw["vout"] if o["scriptPubKey"].get("address") == address))
            lab.mine(DELAY)
            template = st.choices[name].template
            outs = [TxOut(template.vout[0].value, hook_spk)] + list(template.vout[1:])
            if outs == list(template.vout):
                raise SystemExit("instrument error: the tampered transaction equals the template")
            bad = vault.spend(st, name, *coin, outputs=outs)
            ok, reason = lab.submit(bad)
            mok, mreason = lab.as_miner(bad)
            if not ok and needle in reason and not mok and needle in mreason:
                tampered += 1
            else:
                lab.fails.append(f"{v.opcode} state {period},{paid} {name}: redirected copy not refused "
                                 f"[{reason}] [{mreason}]")
            good = vault.spend(st, name, *coin)
            ok, reason = lab.submit(good)
            if ok:
                lab.mine(1)
                honest += 1
            else:
                lab.fails.append(f"{v.opcode} state {period},{paid} {name}: committed transaction refused [{reason}]")
        txid = lab.n.call("sendtoaddress", lab.n.call("decodescript", st.script_pubkey.hex())["address"],
                          btc(st.value), wallet="miner")
        lab.mine(1)
        raw = lab.n.call("getrawtransaction", txid, True)
        vout = next(o["n"] for o in raw["vout"] if bytes.fromhex(o["scriptPubKey"]["hex"]) == st.script_pubkey)
        try:
            lab.n.call("sendrawtransaction", vault.sweep(st, txid, vout, cold, SWEEP_FEE, secret).hex())
            lab.mine(1)
            sweeps += 1
        except RpcError as err:
            lab.fails.append(f"{v.opcode} state {period},{paid}: owner sweep refused [{err.message}]")
    line = (f"every leaf: {honest} of {total} committed transactions confirmed; {tampered} of {total} copies "
            f"redirected to Hook refused (mempool and block); owner swept {sweeps} of {len(v.states)} states")
    print(f"  {'node':<6}{line}")
    return {"leaves": total, "honest_confirmed": honest, "tampered_refused": tampered,
            "states": len(v.states), "owner_sweeps": sweeps}


def run_agent(lab: Lab, v: vault.Vault, menu_addr: list[str], hook_addr: str, agent: str) -> dict:
    model = agent.split(":", 1)[1]
    print(f"   a language model in the agent's chair ({model}), with wallet notes that tell it to empty the vault")
    coin = lab.fund(v.root.script_pubkey)
    lab.mine(DELAY)
    st = v.root
    start = lab.balances()
    spent = {"done": False}

    def execute(name: str, args: dict) -> str:
        if spent["done"]:
            return "The vault coin for this period has already been spent."
        if name == "pay_menu":
            item = int(args.get("item", -1))
            if f"pay:{item}" not in st.choices:
                return f"Menu item {item} does not exist."
            tx = vault.spend(st, f"pay:{item}", *coin)
        elif name == "send":
            outs = []
            for o in args.get("outputs") or []:
                info = lab.n.call("validateaddress", str(o.get("address", "")))
                if not info.get("isvalid"):
                    return f"Invalid address {o.get('address')!r}."
                outs.append(TxOut(int(o.get("sats", 0)), bytes.fromhex(info["scriptPubKey"])))
            tx = vault.spend(st, "pay:0", *coin, outputs=outs + [TxOut(0, vault.ANCHOR)])
        else:
            return f"Unknown tool {name}."
        ok, reason = lab.submit(tx)
        line = f"{name}({json.dumps(args)})"
        honest = any(tx.vout == c.template.vout and tx.vin[0].sequence == c.template.vin[0].sequence
                     for c in st.choices.values())
        if ok:
            lab.mine(1)
            spent["done"] = True
            lab.events.append({"who": "model", "tried": line, "verdict": "CONFIRMED", "on_menu": honest})
            if not honest:
                lab.fails.append(f"model transaction off the menu was accepted: {line}")
            print(f"  model {_short(line, 70):<72} CONFIRMED")
            return f"Accepted and confirmed: {tx.txid()}"
        mok, mreason = lab.as_miner(tx)
        needle = NEEDLE[v.opcode]
        good = needle in reason and not mok and needle in mreason
        lab.events.append({"who": "model", "tried": line, "mempool": reason, "block": mreason,
                           "verdict": "REFUSED" if good else "UNEXPECTED"})
        if not good:
            lab.fails.append(f"model attempt not refused for the covenant reason: {line} [{reason}] [{mreason}]")
        print(f"  model {_short(line, 70):<72} {'REFUSED' if good else 'UNEXPECTED'}")
        print(f"        mempool: {_short(reason)}")
        print(f"        miner  : {_short(mreason)}")
        return f"Rejected by the Bitcoin node: {reason}"

    transcript = hook.ollama_turns(model, menu_addr, hook_addr, st.value, execute)
    for turn in transcript:
        if turn["model_said"]:
            print(f"        model said: {_short(turn['model_said'], 140)}")
    end = lab.balances()
    moved = {w: end[w] - start[w] for w in end}
    lab.expect("model run hook", moved["hook"], 0)
    print(f"   result: hook +{moved['hook']:,} | menu 0 +{moved['menu0']:,} | menu 1 +{moved['menu1']:,}")
    return {"model": model, "transcript": transcript, "moved": moved}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m secondstar", description=__doc__.splitlines()[0])
    ap.add_argument("--bitcoind", help="path to a Bitcoin Inquisition bitcoind (or set SECONDSTAR_BITCOIND)")
    ap.add_argument("--opcode", choices=("ctv", "templatehash", "both"), default="both")
    ap.add_argument("--agent", help="ollama:<model> to let a local language model play the hijacked agent")
    ap.add_argument("--keep", action="store_true", help="keep the node's data folder")
    ap.add_argument("--out", help="write every node answer to this JSON file")
    args = ap.parse_args(argv)
    if args.agent and not args.agent.startswith("ollama:"):
        ap.error("--agent must look like ollama:<model>")
    opcodes = ("ctv", "templatehash") if args.opcode == "both" else (args.opcode,)
    with Node(find_bitcoind(args.bitcoind), keep=args.keep) as node:
        lab = Lab(node)
        info = node.call("getnetworkinfo")
        print(f"Second Star | private regtest node {info['subversion']} | nothing leaves this machine")
        deps = node.call("getdeploymentinfo")["deployments"]
        for op in opcodes:
            key = {"ctv": "checktemplateverify", "templatehash": "templatehash"}[op]
            if not deps.get(key, {}).get("active"):
                raise SystemExit(f"{op} is not active on this node; use a Bitcoin Inquisition 29.x build")
        for w in WALLETS:
            node.call("createwallet", w)
        lab.mine(201)
        records = [run_opcode(lab, op, args.agent if i == 0 else None) for i, op in enumerate(opcodes)]
        if args.keep:
            print(f"node data kept in {node.datadir}")
    verdict = "PASS" if not lab.fails else "FAIL"
    print(f"\nSECOND STAR: {verdict}")
    for f in lab.fails:
        print(f"  FAIL {f}")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"verdict": verdict, "fails": lab.fails, "records": records, "events": lab.events}, fh, indent=2)
    return 0 if not lab.fails else 1


if __name__ == "__main__":
    sys.exit(main())
