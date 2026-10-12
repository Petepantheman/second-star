"""Second Star on Lightning: three ways to let a covenant allowance reach an AI agent's Lightning wallet, each attacked.

    python -m secondstar.lightning_run --bitcoind /path/to/bitcoind --lnd /path/to/lnd

Five Lightning nodes on a throwaway regtest node: the agent, a swap provider (who also routes), a shop selling a paid
API, Hook, and a small node on the owner's side. Hook takes over the agent's machine and wants the vault's money.

  Act 1, plain wallet   the vault pays each tranche to the agent's own on-chain address.
  Act 2, naive swap     the vault pays a swap lock; the agent's node holds the swap secret.
  Act 3, held swap      the vault pays a swap lock; the owner's node holds a hold invoice for it and settles only once
                        the provider's payment is held there, then pays the agent's node by its fixed key. The swap's
                        hash and secret never touch the agent's machine.

Everything the run claims is checked against the nodes; it exits non-zero if anything is off.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import threading
import time

from . import htlc, secp, vault
from .__main__ import Lab, NEEDLE
from .lightning import LightningNode, find_lnd
from .node import Node, find_bitcoind
from .paid_api import PaidAPI, call, pay
from .prove import prove
from .tx import TxOut

FUNDING, TRANCHE, PERIODS, DELAY = 1_000_000, 100_000, 3, 3
SWAP_FEE, CLAIM_FEE, REFUND_DELAY, FINAL_CLTV, MARGIN = 1_000, 500, 144, 40, 12
LND_PADDING = 3        # LND adds 3 blocks to the final CLTV delta when it builds the route
PRICE = 1_000


class Run:
    def __init__(self, chain: Node, lab: Lab, nodes: dict[str, LightningNode], opcode: str):
        self.chain, self.lab, self.ln, self.opcode = chain, lab, nodes, opcode
        self.fails: list[str] = []
        self.events: list[dict] = []
        self.owner_secret = self._key()
        self.provider_secret = self._key()
        self.hook_secret = self._key()
        self.cold_x, self.provider_x = secp.pubkey(self.owner_secret), secp.pubkey(self.provider_secret)
        self.cold_spk = lab.spk(lab.addr("owner"))
        self.hook_spk = lab.spk(lab.addr("hook"))

    @staticmethod
    def _key() -> int:
        return int.from_bytes(os.urandom(32), "big") % secp.N or 1

    # ---- reporting ----------------------------------------------------------------------------------------------
    def check(self, label: str, ok: bool, detail: str = "") -> bool:
        print(f"  {label:<84} {'OK' if ok else 'FAIL'}" + (f"   {detail}" if detail else ""))
        self.events.append({"check": label, "ok": ok, "detail": detail})
        if not ok:
            self.fails.append(f"{label}: {detail}")
        return ok

    def refused(self, label: str, tx, needle: str, block_needle: str | None = None, package: bool = False) -> None:
        """Refused by the mempool (alone, or as a package with a fee child for zero-fee covenant transactions) and
        by a block the node's own miner tries to build."""
        ok_m, why_m = self.lab.submit(tx) if package else self.lab.test_alone(tx)
        ok_b, why_b = self.lab.as_miner(tx)
        good = not ok_m and not ok_b and needle in why_m and (block_needle or needle) in why_b
        self.check(label, good, f"mempool: {why_m.strip()[:60]} | block: {why_b.strip()[:60]}")

    # ---- chain and Lightning helpers ---------------------------------------------------------------------------
    def mine(self, n: int) -> None:
        self.lab.mine(n)
        for node in self.ln.values():
            node.wait_synced()

    def local(self, who: str) -> int:
        return self.ln[who].local_balance()

    def open(self, frm: str, to: str, amount: int) -> None:
        a, b = self.ln[frm], self.ln[to]
        try:
            a.cli("connect", f"{b.pubkey}@127.0.0.1:{b.p2p}")
        except RuntimeError as err:
            if "already connected" not in str(err):
                raise
        a.cli("openchannel", "--node_key", b.pubkey, "--local_amt", str(amount))

    def wait_active(self, who: str, n: int) -> None:
        for _ in range(120):
            chans = self.ln[who].cli("listchannels").get("channels", [])
            if len(chans) >= n and all(c.get("active") for c in chans):
                return
            time.sleep(1)
        raise SystemExit(f"{who}: channels never became active")

    def height(self) -> int:
        return self.chain.call("getblockcount")

    def conf_height(self, txid: str) -> int:
        raw = self.chain.call("getrawtransaction", txid, True)
        return self.chain.call("getblockheader", raw["blockhash"])["height"]

    def wallet_sats(self, wallet: str) -> int:
        return self.lab.balance(wallet)

    # ---- vaults -------------------------------------------------------------------------------------------------
    def vault_with_locks(self, seed: bytes):
        locks = [htlc.lock(htlc.preimage_pair(seed, k)[1], self.provider_x, self.cold_x, REFUND_DELAY)
                 for k in range(PERIODS)]
        v = vault.build(FUNDING, TRANCHE, PERIODS, DELAY, [], self.cold_spk, self.cold_x, self.opcode,
                        menus=[[lk.script_pubkey] for lk in locks])
        return v, locks

    def release(self, state: vault.State, coin: tuple[str, int], label: str):
        """Wait out the delay and broadcast the state's one menu payment. Returns the payment transaction."""
        self.mine(DELAY)
        tx = vault.spend(state, "pay:0", *coin)
        ok, why = self.lab.submit(tx)
        self.check(label, ok, why[:60])
        self.mine(1)
        return tx

    def keysend(self, frm: str, to: str, amount: int) -> None:
        """Pay a node by its public key alone (no invoice from the receiver). Retries only while a fresh link is not
        ready; the caller checks the receiver's balance."""
        dest, last = self.ln[to].pubkey, ""
        for _ in range(15):
            try:
                out = self.ln[frm].cli("sendpayment", "--dest", dest, "--amt", str(amount), "--keysend", "--force",
                                       "--json")
                if out.get("status") == "SUCCEEDED":
                    return
                last = str(out)[:200]
            except RuntimeError as err:
                last = str(err)
            time.sleep(2)
        raise SystemExit(f"{frm}: keysend to {to} failed: {last[:300]}")

    # ---- the provider's side of a swap --------------------------------------------------------------------------
    def deadline_ok(self, decoded: dict, lock_conf: int) -> tuple[bool, str]:
        """The provider's first rule: even on a direct channel the payment would expire at tip + the invoice's final
        CLTV delta + LND's 3-block padding; that plus a margin must come before the owner's refund opens."""
        expiry = self.height() + int(decoded["cltv_expiry"]) + LND_PADDING
        return expiry + MARGIN < lock_conf + REFUND_DELAY, (f"earliest HTLC expiry {expiry} + margin {MARGIN} vs "
                                                            f"refund opens at {lock_conf + REFUND_DELAY}")

    def outgoing_expiry(self, payment_hash: bytes) -> int | None:
        """The absolute expiry of the provider's own outgoing HTLC for this hash, read from its channels."""
        forms = {payment_hash.hex(), base64.b64encode(payment_hash).decode()}
        for _ in range(120):
            for ch in self.ln["provider"].cli("listchannels").get("channels", []):
                for h in ch.get("pending_htlcs", []):
                    if h.get("hash_lock") in forms and not h.get("incoming"):
                        return int(h["expiration_height"])
            time.sleep(0.5)
        return None

    def provider_pays_and_claims(self, payment_request: str, lock: htlc.SwapLock, outpoint: tuple[str, int],
                                 lock_conf: int, settle=None, cancel=None) -> bytes | None:
        """Check the invoice against the lock and the deadline; if both hold, pay it with a CLTV cap that keeps every
        route's expiry before the refund, learn the preimage and claim the lock. If the payment's real expiry still
        comes out too late, the swap is called off before anything settles: `cancel` cancels the invoice and the
        payment goes back to the provider. Returns None whenever the swap does not go ahead."""
        prov = self.ln["provider"]
        decoded = prov.cli("decodepayreq", payment_request)
        if decoded["payment_hash"] != lock.payment_hash.hex() or int(decoded["num_satoshis"]) != TRANCHE - SWAP_FEE:
            raise SystemExit("provider: invoice does not match the swap lock")
        ok, detail = self.deadline_ok(decoded, lock_conf)
        self.check("provider: the invoice fits before the owner's refund opens, so it pays (with a CLTV cap)", ok,
                   detail)
        if not ok:
            return None
        refund_open = lock_conf + REFUND_DELAY
        limit = refund_open - MARGIN - 1 - self.height()
        result: dict = {}
        worker = threading.Thread(target=lambda: result.update(pre=pay(prov, payment_request, cltv_limit=limit)),
                                  daemon=True)
        worker.start()
        expiry = self.outgoing_expiry(lock.payment_hash)
        in_time = expiry is not None and expiry + MARGIN < refund_open
        self.check("provider: its payment's real expiry, read from its own channel, is before the refund opens",
                   in_time,
                   f"HTLC expires at {expiry} (cap {limit} blocks) + margin {MARGIN} vs refund opens at {refund_open}")
        if not in_time:
            if cancel:
                cancel()
            worker.join(timeout=60)
            return None
        if settle:
            settle()
        worker.join(timeout=180)
        learned = bytes.fromhex(result["pre"])
        if hashlib.sha256(learned).digest() != lock.payment_hash:
            raise SystemExit("provider: the learned preimage does not open the lock")
        claim = htlc.claim_tx(lock, outpoint, TRANCHE, self.lab.spk(prov.new_address()), CLAIM_FEE,
                              self.provider_secret, learned)
        self.chain.call("sendrawtransaction", claim.hex())
        self.mine(1)
        return learned


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m secondstar.lightning_run", description=__doc__.splitlines()[0])
    ap.add_argument("--bitcoind")
    ap.add_argument("--lnd", help="path to lnd (lncli must sit next to it), or set SECONDSTAR_LND")
    ap.add_argument("--opcode", choices=vault.OPCODES, default="ctv")
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    lnd, lncli = find_lnd(args.lnd)
    with Node(find_bitcoind(args.bitcoind), zmq=True) as chain:
        lab = Lab(chain)
        for w in ("miner", "owner", "hook"):
            chain.call("createwallet", w)
        lab.mine(201)
        nodes = {name: LightningNode(name, chain, lnd, lncli)
                 for name in ("agent", "provider", "shop", "hook", "owner")}
        try:
            for node in nodes.values():
                node.start()
            run = Run(chain, lab, nodes, args.opcode)
            return play(run, args)
        finally:
            for node in nodes.values():
                node.stop()


def play(run: Run, args) -> int:
    chain, lab, ln = run.chain, run.lab, run.ln
    print(f"Second Star on Lightning | {chain.call('getnetworkinfo')['subversion']} + lnd "
          f"{ln['agent'].cli('getinfo')['version'].split()[0]} | private regtest, nothing leaves this machine")
    chain.call("sendtoaddress", ln["provider"].new_address(), "0.1", wallet="miner")
    chain.call("sendtoaddress", ln["shop"].new_address(), "0.02", wallet="miner")
    chain.call("sendtoaddress", ln["owner"].new_address(), "0.01", wallet="miner")
    run.mine(1)
    for frm, to, amt in (("provider", "agent", 1_000_000), ("provider", "shop", 1_000_000),
                         ("provider", "hook", 1_000_000), ("provider", "owner", 1_000_000),
                         ("shop", "provider", 500_000), ("owner", "provider", 500_000)):
        run.open(frm, to, amt)
        run.mine(1)
    run.mine(6)
    for who, n in (("provider", 6), ("agent", 1), ("shop", 2), ("hook", 1), ("owner", 2)):
        run.wait_active(who, n)
    print("   network: provider -> agent, shop, Hook, owner (1,000,000 each); shop, owner -> provider (500,000 each)")
    outcome = {}

    # == Act 1: plain wallet =========================================================================================
    print("\n== Act 1: the vault pays the agent's own on-chain wallet")
    agent_addr = ln["agent"].new_address("p2wkh")
    v1 = vault.build(FUNDING, TRANCHE, PERIODS, DELAY, [lab.spk(agent_addr)], run.cold_spk, run.cold_x, run.opcode)
    c1 = lab.fund(v1.root.script_pubkey)
    run.release(v1.root, c1, "vault: tranche 1 lands in the agent's on-chain wallet")
    for _ in range(30):
        if ln["agent"].onchain() >= TRANCHE:
            break
        time.sleep(1)
    hook_before = run.wallet_sats("hook")
    ln["agent"].cli("sendcoins", "--addr", lab.addr("hook"), "--sweepall")
    run.mine(1)
    took = run.wallet_sats("hook") - hook_before
    left = ln["agent"].onchain()
    run.check("plain: Hook, alone, sends the tranche to himself on-chain (LND keeps a small fee reserve back)",
              took >= TRANCHE - 10_000 - 5_000 and took + left <= TRANCHE,
              f"Hook +{took:,}, left in the agent's wallet {left:,}, sweep fee {TRANCHE - took - left:,}")
    outcome["plain"] = took

    # == Act 2: naive swap (the agent's node holds the secret) ======================================================
    print("\n== Act 2: the vault pays a swap lock, and the agent's node holds the swap secret")
    seed_n = os.urandom(32)
    v2, locks2 = run.vault_with_locks(seed_n)
    c2 = lab.fund(v2.root.script_pubkey)
    pay2 = run.release(v2.root, c2, "vault: tranche 1 goes into swap lock 1")
    p0, _ = htlc.preimage_pair(seed_n, 0)
    inv = ln["agent"].cli("addinvoice", "--amt", str(TRANCHE - SWAP_FEE), "--preimage", p0.hex())
    leaked = bytes.fromhex(ln["agent"].cli("lookupinvoice", inv["r_hash"]).get("r_preimage", "") or "00")
    run.check("naive: Hook reads the swap secret straight out of the agent's node", leaked == p0)
    prov_before = ln["provider"].onchain()
    agent_ln_before = run.local("agent")
    claim = htlc.claim_tx(locks2[0], (pay2.txid(), 0), TRANCHE, lab.spk(ln["provider"].new_address()), CLAIM_FEE,
                          run.provider_secret, leaked)
    chain.call("sendrawtransaction", claim.hex())
    run.mine(1)
    for _ in range(30):
        if ln["provider"].onchain() > prov_before:
            break
        time.sleep(1)
    gained = ln["provider"].onchain() - prov_before
    run.check("naive: Hook hands it to a colluding provider, who takes the tranche without paying",
              gained == TRANCHE - CLAIM_FEE and run.local("agent") == agent_ln_before,
              f"provider +{gained:,} on-chain, agent +{run.local('agent') - agent_ln_before} over Lightning")
    outcome["naive"] = gained

    # == Act 3: held swap (the design) ===============================================================================
    print("\n== Act 3: the vault pays a swap lock; the owner's node holds a hold invoice for it and pays the agent "
          "once the provider has paid")
    seed = os.urandom(32)                       # the owner's signer keeps this; nothing on the agent's machine sees it
    v, locks = run.vault_with_locks(seed)
    cert = prove(vault.describe(v), dict(vault.claims(v), swap_locks=htlc.describe(locks)))
    run.check(f"prover: {v.opcode.upper()} vault whose menu is exactly one swap lock per payment, each refunding "
              f"to the owner", cert["verdict"] == "PROVED" and "swap lock" in cert["statement"],
              f"most to the menu after 1/2/3 steps: {list(cert['most_paid_after_k_steps'].values())}")
    coin = lab.fund(v.root.script_pubkey)
    ok, why = lab.submit(vault.spend(v.root, "pay:0", *coin))
    run.check("vault: no refill before the wait is over", not ok and "non-BIP68-final" in why, why[:50])
    staircase = [run.local("agent")]

    def agent_secrets() -> set[bytes]:
        """Every payment secret on the agent's machine: its invoices (keysend ones included) and its payments."""
        found = set()
        for inv in ln["agent"].cli("listinvoices", "--max_invoices", "10000").get("invoices", []):
            if inv.get("r_preimage"):
                found.add(bytes.fromhex(inv["r_preimage"]))
        for p_ in ln["agent"].cli("listpayments", "--include_incomplete").get("payments", []):
            if p_.get("payment_preimage") and set(p_["payment_preimage"]) != {"0"}:
                found.add(bytes.fromhex(p_["payment_preimage"]))
        return found

    def agent_knows_hash(h: bytes) -> bool:
        try:
            ln["agent"].cli("lookupinvoice", h.hex())
            return True
        except RuntimeError:
            return False

    def held_refill(k: int, pay_tx) -> None:
        lock, outpoint = locks[k], (pay_tx.txid(), 0)
        conf = run.conf_height(pay_tx.txid())
        p, h = htlc.preimage_pair(seed, k)
        hold = ln["owner"].cli("addholdinvoice", h.hex(), "--amt", str(TRANCHE - SWAP_FEE),
                               "--cltv_expiry_delta", str(FINAL_CLTV), "--memo", f"refill {k + 1}")
        if k == 1:      # by now Hook controls the agent's whole machine
            dump = agent_secrets()
            to = lab.spk(ln["provider"].new_address())
            refusals = []
            for secret in sorted(dump) + [bytes(32)]:
                tx = htlc.claim_tx(lock, outpoint, TRANCHE, to, CLAIM_FEE, run.provider_secret, secret)
                ok_m, why_m = lab.test_alone(tx)
                ok_b, why_b = lab.as_miner(tx)
                refusals.append(not ok_m and not ok_b and "EQUALVERIFY" in why_m and "EQUALVERIFY" in why_b)
            run.check(f"held 2: Hook hands every secret on the agent's machine to a dishonest provider; none opens "
                      f"the lock", len(dump) > 0 and all(refusals),
                      f"{sum(refusals)}/{len(refusals)} claims refused by mempool and miner ({len(dump)} secrets + zero)")
            guess = htlc.claim_tx(lock, outpoint, TRANCHE, run.hook_spk, CLAIM_FEE, run.hook_secret, os.urandom(32))
            run.refused("held 2: Hook cannot open the lock with a guess", guess, "EQUALVERIFY")
            sneaky = htlc.refund_tx(lock, outpoint, TRANCHE, run.hook_spk, CLAIM_FEE, run.hook_secret)
            run.refused("held 2: nobody can use the refund path before its delay", sneaky, "non-BIP68-final",
                        "bad-txns-nonfinal")

        def signer() -> None:
            """The owner's signer reads only the owner's own node, which Hook does not control."""
            for _ in range(120):
                inv = ln["owner"].cli("lookupinvoice", h.hex())
                if inv.get("state") == "ACCEPTED" and int(inv.get("amt_paid_sat", 0)) == TRANCHE - SWAP_FEE:
                    ln["owner"].cli("settleinvoice", p.hex())
                    return
                time.sleep(0.5)
            raise SystemExit("signer: the provider's payment never arrived")

        before = run.local("agent")
        run.provider_pays_and_claims(hold["payment_request"], lock, outpoint, conf, settle=signer,
                                     cancel=lambda: ln["owner"].cli("cancelinvoice", h.hex()))
        settled = ln["owner"].cli("lookupinvoice", h.hex())
        run.keysend("owner", "agent", TRANCHE - SWAP_FEE)
        for _ in range(30):
            if run.local("agent") - before >= TRANCHE - SWAP_FEE:
                break
            time.sleep(1)
        gained = run.local("agent") - before
        run.check(f"held {k + 1}: the owner's node settles only once the provider's payment is held there, then pays "
                  f"the agent's node", settled.get("state") == "SETTLED" and gained == TRANCHE - SWAP_FEE,
                  f"owner invoice {settled.get('state')}, agent +{gained:,} over Lightning")
        secrets = agent_secrets()
        run.check(f"held {k + 1}: the swap's hash and secret never touched the agent's machine",
                  not agent_knows_hash(h) and p not in secrets,
                  f"{len(secrets)} secrets on the agent's node, none is the swap's")

    print("   period 1")
    pay1 = run.release(v.root, coin, "vault: tranche 1 goes into swap lock 1")
    held_refill(0, pay1)
    staircase.append(run.local("agent"))

    api = PaidAPI(ln["shop"], PRICE)
    served = [call(api.url, ln["agent"], max_cost_sats=2 * PRICE)[0] for _ in range(5)]
    run.check("paid API: 5 calls at 1,000 sats, each paid over Lightning and served", served == [200] * 5, str(served))
    code, body = call(api.url, ln["agent"], max_cost_sats=PRICE // 2)
    run.check("software cap: an honest client refuses a call above its cap", code == 0, str(body)[:60])
    api.close()

    before = run.local("agent")
    tip = ln["agent"].cli("addinvoice", "--amt", "50000", "--memo", "a tip")
    pay(ln["shop"], tip["payment_request"])
    vault_coin = (pay1.txid(), 1)
    run.check("inbound: the shop tips the agent 50,000 sats; the vault does not move",
              run.local("agent") - before == 50_000 and chain.call("gettxout", *vault_coin) is not None,
              f"agent +{run.local('agent') - before:,}")

    print("   Hook takes over the agent's machine")
    hook_ln_before = run.local("hook")
    take = run.local("agent") - 20_000
    pay(ln["agent"], ln["hook"].cli("addinvoice", "--amt", str(take), "--memo", "loot")["payment_request"])
    run.check("hijack: Hook drains what the agent's Lightning wallet already holds",
              run.local("hook") - hook_ln_before == take, f"Hook +{take:,}")
    st1 = v.states[(1, 1)]
    ok, why = lab.submit(vault.spend(st1, "pay:0", *vault_coin))
    run.check("hijack: Hook cannot release the next tranche before its wait", not ok and "non-BIP68-final" in why,
              why[:50])

    print("   period 2")
    run.mine(DELAY)
    drain = vault.spend(st1, "pay:0", *vault_coin, outputs=[TxOut(st1.value, run.hook_spk), TxOut(0, vault.ANCHOR)])
    run.refused("hijack: even after the wait, Hook cannot make the vault pay him", drain, NEEDLE[v.opcode],
                package=True)
    tx = vault.spend(st1, "pay:0", *vault_coin)
    ok, why = lab.submit(tx)
    run.check("vault: tranche 2 goes into swap lock 2", ok, why[:50])
    run.mine(1)
    held_refill(1, tx)
    staircase.append(run.local("agent"))
    take = run.local("agent") - 20_000
    pay(ln["agent"], ln["hook"].cli("addinvoice", "--amt", str(take), "--memo", "loot 2")["payment_request"])
    hook_total = run.local("hook") - hook_ln_before
    owner_before = run.wallet_sats("owner")
    st2 = v.states[(2, 2)]
    chain.call("sendrawtransaction", vault.sweep(st2, tx.txid(), 1, run.cold_spk, CLAIM_FEE, run.owner_secret).hex())
    run.mine(1)
    run.check("owner notices and sweeps the rest of the vault home",
              run.wallet_sats("owner") - owner_before == st2.value - CLAIM_FEE,
              f"+{run.wallet_sats('owner') - owner_before:,}")
    print("   a second deposit to the same vault (the limit: fund each swap vault once)")
    c_again = lab.fund(v.root.script_pubkey)
    pay_again = run.release(v.root, c_again, "vault: a second coin's tranche 1 goes into the same swap lock 1")
    p_known, _ = htlc.preimage_pair(seed, 0)                  # public since the first claim put it on-chain
    prov_before = ln["provider"].onchain()
    free = htlc.claim_tx(locks[0], (pay_again.txid(), 0), TRANCHE, lab.spk(ln["provider"].new_address()),
                         CLAIM_FEE, run.provider_secret, p_known)
    chain.call("sendrawtransaction", free.hex())
    run.mine(1)
    for _ in range(30):
        if ln["provider"].onchain() > prov_before:
            break
        time.sleep(1)
    run.check("limit: the provider can claim a reused swap lock without paying, because its secret is public",
              ln["provider"].onchain() - prov_before == TRANCHE - CLAIM_FEE,
              f"provider +{ln['provider'].onchain() - prov_before:,}")
    bound = 2 * (TRANCHE - SWAP_FEE) + 50_000
    run.check("held: everything Hook got <= the refills that reached the wallet + money from outside",
              hook_total <= bound, f"Hook +{hook_total:,} <= {bound:,}")
    outcome["held"] = hook_total

    print("   a provider that will not pay: this invoice could still be pending when the refund opens (a fourth vault)")
    seed4 = os.urandom(32)
    v4, locks4 = run.vault_with_locks(seed4)
    c4 = lab.fund(v4.root.script_pubkey)
    pay4 = run.release(v4.root, c4, "vault 4: tranche 1 goes into its swap lock")
    lock4 = (pay4.txid(), 0)
    late = ln["owner"].cli("addholdinvoice", htlc.preimage_pair(seed4, 0)[1].hex(), "--amt",
                           str(TRANCHE - SWAP_FEE), "--cltv_expiry_delta", "140")
    decoded = ln["provider"].cli("decodepayreq", late["payment_request"])
    ok, detail = run.deadline_ok(decoded, run.conf_height(pay4.txid()))
    run.check("provider: refuses to pay an invoice that could still be pending when the owner's refund opens",
              not ok, detail)
    refund = htlc.refund_tx(locks4[0], lock4, TRANCHE, run.cold_spk, CLAIM_FEE, run.owner_secret)
    ok, why = lab.test_alone(refund)
    run.check("refund: the owner must wait the full refund delay", not ok and "non-BIP68-final" in why, why.strip()[:50])
    run.mine(REFUND_DELAY)
    run.refused("refund: after the delay, Hook still cannot use the owner's refund",
                htlc.refund_tx(locks4[0], lock4, TRANCHE, run.hook_spk, CLAIM_FEE, run.hook_secret),
                "Invalid Schnorr signature")
    owner_before = run.wallet_sats("owner")
    chain.call("sendrawtransaction", refund.hex())
    run.mine(1)
    back = run.wallet_sats("owner") - owner_before
    run.check("refund: the tranche goes back to the owner, never the agent", back == TRANCHE - CLAIM_FEE, f"+{back:,}")

    verdict = "PASS" if not run.fails else "FAIL"
    print("\n   who can take a refill once Hook controls the agent's machine")
    print(f"     plain wallet : Hook alone. Measured: Hook +{outcome.get('plain', 0):,} sats on-chain.")
    print(f"     naive swap   : Hook plus a dishonest provider. Measured: Hook copied the secret from the agent's "
          f"node; provider +{outcome.get('naive', 0):,}, agent +0.")
    print("     held swap    : nobody, even Hook with the agent's whole machine plus a dishonest provider (measured: "
          "every secret on the machine tried, all refused).")
    print("                    Hook still gets whatever already reached the agent's Lightning wallet "
          f"(measured: +{outcome.get('held', 0):,} over two periods, two refills and a tip).")
    print(f"   agent balance right after each held refill (Hook drained in between): "
          f"{', '.join(f'{x:,}' for x in staircase)}")
    print(f"SECOND STAR ON LIGHTNING: {verdict}")
    for f in run.fails:
        print(f"  FAIL {f}")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"verdict": verdict, "fails": run.fails, "events": run.events, "outcome": outcome,
                       "staircase": staircase}, fh, indent=2)
    return 0 if not run.fails else 1


if __name__ == "__main__":
    sys.exit(main())
