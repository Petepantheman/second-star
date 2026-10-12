# Limits

Read this before you believe anything in the README.

## 1. On Bitcoin mainnet today, these addresses are not safe

Neither covenant opcode is enforced on Bitcoin mainnet. There, a revealed CTV leaf (`<32 bytes> 0xb3`) runs `0xb3` as
a no-op, leaves the hash on the stack, and succeeds. A revealed TEMPLATEHASH leaf (`<32 bytes> 0xce 0x87`) succeeds
before it runs at all, because `0xce` is `OP_SUCCESS206`. Spending takes the leaf script and its control block. They
are revealed by the first spend, and anyone with the vault description has them already. After that, anyone can take
the coins. **Never send real bitcoin to a Second Star address.** Everything here runs on a private regtest node from
Bitcoin Inquisition, where `getdeploymentinfo` reports both deployments active.

As of 2026-10-11, no mainnet miner is signalling for BIP-119. [bip119monitor.com](https://bip119monitor.com/) shows 0
signalling blocks in every period it tracks since block 939,456. A competing draft,
[BIP-448](https://github.com/bitcoin/bips/blob/master/bip-0448.md), would deploy TEMPLATEHASH together with
CHECKSIGFROMSTACK and INTERNALKEY. That is why the vault is built both ways.

## 2. The menu is written before the coins are locked

Each period the coins can pay one address from a list, for an exact amount, or pay nobody. If an invoice for a new
address shows up later, the vault cannot pay it. The owner has to sweep the coins and lock a new vault. This is a
known property of template covenants: a template fixes outputs ahead of time. Proposals like CHECKCONTRACTVERIFY let a
spend choose its destination when it is triggered. See the vault comparison in [PRIOR-ART.md](PRIOR-ART.md).

## 3. The menu is the blast radius

The agent holds no key, but the covenant witness is public. Whoever can broadcast (the agent, a thief on its machine,
anyone who has the vault description) can pick which menu item gets paid each period, or skip. So a hijacked agent can
still pay the *wrong item on the menu*. It cannot pay anyone off the menu, pay more than the tranche, or go faster than
the timelock. Keep the menu to addresses you would be fine paying in the worst case.

## 4. The owner's key is all-powerful

The cold leaf lets the owner sweep everything at any time, with no wait. If that key is stolen, the thief can do the
same. Treat it like cold storage, because it is.

## 5. Fees come from a child transaction

Covenant transactions are version 3, pay zero fee, and carry a 0-value pay-to-anchor output. Whoever broadcasts adds a
child that spends the anchor and pays the miner. That needs relay policy that is not consensus: TRUC (version 3) and
pay-to-anchor shipped in Bitcoin Core 28.0, and the 0-value "ephemeral dust" anchor in 29.0. Inquisition 29.x has all
three. The run shows transactions that break those rules. A version-2 rewrite falls outside TRUC, so the mempool
returns `min relay fee not met`. Taking a fee from the vault puts a non-zero fee next to the dust anchor, so the
ephemeral-dust policy returns `dust, tx with dust output must be 0-fee`. A miner can still mine a covenant transaction
without its child, because that is consensus-valid. The 0-value anchor is then left behind as a dust output.

## 6. Time is counted in blocks, not days

The wait is a BIP-68 relative timelock of `delay` blocks after the previous step confirmed. Miners can delay a
payment by refusing to mine it. They cannot redirect it.

## 7. One coin of exactly the planned amount

The templates commit to exact output amounts, and the covenant never sees the coin it spends. So the guarantee is per
coin:

- **More than planned:** the honest transactions now leave a fee next to a 0-value anchor, so the relay network refuses
  them. A miner can still include one, and keeps the excess.
- **Less than planned:** no template can be satisfied, and only the owner can move the coin.
- **A second deposit:** it is a second allowance with the same limits, so two coins at the address allow twice the
  rate.

Fund each vault once, with exactly the planned amount.

## 8. The tree grows with the schedule

There is one vault per (period, payments made so far) pair: `periods × (periods + 1) / 2` vaults. 3 periods is 6
vaults, 12 is 78, 52 weekly periods is 1,378. All of it is computed offline before funding.

## 9. The crypto in this repo is for test networks

`secp.py` is a short pure-Python secp256k1 / BIP-340 / BIP-341 implementation. It passes every official BIP-340
vector, and the node accepts its signatures and addresses, but it is slow and not hardened against side channels.

## 10. What the proof does and does not cover

See [PROOF.md](PROOF.md). The prover checks the vault's actual bytes for every state it can reach. It does not check
Bitcoin's consensus rules themselves; it assumes the node implements BIP-68, BIP-341/342, BIP-119 and BIP-446 as
written. The node run is the evidence for that assumption on this build: every covenant leaf of every state was spent on the
node, each committed transaction confirmed, and a copy redirected to an attacker was refused, both by the mempool and
by a miner-built block.

## 11. On CTV, the witness is not committed

BIP-119 hashes the transaction's version, locktime, sequences and outputs, but not its witness. So anyone can append a
Taproot annex to an honest CTV payment. Relay refuses it (`bad-witness-nonstandard`), but a miner can confirm it. The
run measures this: the payment confirms with the annex attached, and the money goes exactly where the template says.
BIP-446 commits to the annex, so the TEMPLATEHASH vault refuses the same transaction at both levels.

## 12. A quantum computer could take the vault through its Taproot key

Every vault is a Taproot output. Its key is `Q = H + tG`, where nobody knows the discrete log of the unspendable point
`H`. That stops honest people from signing, but Shor's algorithm would recover the discrete log of `Q` itself, which
is on-chain from the moment the vault is funded. A key-path signature for `Q` skips every leaf. The covenant leaves are
hash-only and are not the weak point. The owner's key becomes a second exposure once a sweep or a refund puts it
on-chain; from then on, that one key can sweep every vault and refund every swap lock that uses it.
[BIP-360](https://github.com/bitcoin/bips/blob/master/bip-0360.mediawiki) (Pay-to-Merkle-Root, Draft) removes the key
path for exactly this reason. It is not active on Bitcoin Inquisition 29.4, so a quantum-resistant vault cannot be
built and tested here yet. Lightning has the same exposure through its channel and node keys.

## 13. Lightning has its own limits

Connecting the allowance to an agent's Lightning wallet adds limits of its own: whatever reaches the wallet is hot,
the owner's side becomes a trusted online part, stealing a refill through a swap needs a dishonest provider, and each
swap vault must be funded exactly once. They are listed with their measurements in [LIGHTNING.md](LIGHTNING.md).
