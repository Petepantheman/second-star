# What the prover proves

`python -m secondstar.prove vault.json claims.json` reads a vault from its raw bytes and prints either `PROVED` with a
certificate, or `REFUTED` with the reasons. `secondstar/prove.py` shares no code with the builder. It has its own
transaction parser, its own copies of both template hashes and its own Taproot tree and tweak arithmetic, and it
derives the unspendable internal key from the curve generator instead of pasting a constant.

## The statement

Take a vault built with funding `F`, tranche `T`, `P` periods, a delay of `d ≥ 1` blocks, a menu `M` and an owner
address `C`. If the prover says `PROVED`, then under the assumptions below:

> For **one coin of exactly `F` sats** at the root address, without the owner's key: the coin can only ever pay
> addresses in `M`, the owner's address `C`, or a 0-value anchor. Each step pays the menu at most `T`. Each step needs
> the previous one buried `d` blocks deep, so `t` blocks after the coin confirms, the menu has received at most
> `T × min(⌊t/d⌋, P)`. Every sat not paid to the menu stays in the vault or goes to `C`.

Two consequences follow, and they are not loopholes in the prover. The covenant hashes commit to the spending
transaction, never to the coin being spent.

- **Each further coin sent to the root address is a separate allowance with the same limits.** Two deposits of `F`
  allow `2T` per period.
- **Sats above `F` in a coin go to a miner as fee.** The relay network refuses such a transaction (a fee next to a
  0-value anchor breaks the ephemeral-dust policy), but a miner can include it and keep the excess. A coin with less
  than `F` cannot follow any template; only the owner can move it.

## How it gets there

For every vault reachable from the root, the prover checks:

1. **No key path.** The address is a Taproot output whose internal key is BIP-341's point `H`. The prover derives `H`
   as SHA-256 of the uncompressed generator. Nobody knows its discrete log.
2. **No hidden leaf.** The Merkle root is rebuilt from the listed leaves and the listed tree shape alone, using every
   leaf exactly once and leaf version `0xc0`, then tweaked into the key. The result has to equal the address. A leaf
   that is not listed would change the root.
3. **Only known leaf shapes.** Each leaf must be exactly one of
   `<32-byte hash> OP_CHECKTEMPLATEVERIFY`, `<32-byte hash> OP_TEMPLATEHASH OP_EQUAL`, or
   `<owner key> OP_CHECKSIG`. There must be exactly one owner leaf, the owner key must be a valid curve point, and no
   leaf may sit deeper than 128 (the BIP-341 limit), so the owner's leaf can always be spent. Anything else fails,
   because an unknown leaf could be a back door (an `OP_SUCCESS` byte, a stranger's key, `OP_TRUE`).
4. **Each covenant leaf has one transaction.** The leaf's hash must equal the BIP-119 or BIP-446 hash of a listed
   transaction. That transaction must have one input, an empty scriptSig, version 2 or higher, nLockTime 0, and an
   nSequence that is exactly a `d`-block relative lock.
5. **Each transaction pays only the plan.** Its outputs must go to a menu address (at most `T` in total), to at most
   one next vault, to the owner, or to a 0-value anchor. Every value must lie between 0 and 21 million BTC, and the
   outputs must add up to exactly what the vault holds.
6. **The graph is finite and consistent.** Every vault reached is described, every described vault is reached, each
   vault is always reached with the same amount, and there are no cycles. The prover then walks every path and records
   the most the menu can receive after `k` steps. For the default vault that is 100,000 / 200,000 / 300,000 sats after
   1 / 2 / 3 steps.
7. **The claims are sane.** They must be integers in range (`d` from 1 to 65,535) with a non-empty menu. A `NaN` or
   `Infinity` in the JSON is rejected.

The test suite feeds it 23 deliberately broken vaults and 7 sets of bad claims. Each one comes back `REFUTED` for the
right reason. The broken vaults include a hidden key leaf, an unlisted leaf, an `OP_TRUE` leaf, a real key on the key
path, payments to a stranger, a double tranche, a missing, disabled or time-based timelock, version 1, an absolute
locktime, a split into two vaults, a leak to fees, a funded anchor, a negative output, a vault reached with two
amounts, an owner leaf at depth 129, and a template that does not match its hash.

## Assumptions

- **A1.** Nobody knows the discrete log of `H`.
- **A2.** SHA-256 is collision resistant. No second transaction has the same template hash, and no second tree has the
  same root.
- **A3.** BIP-340 signatures cannot be forged without the owner's secret key.
- **A4.** The chain enforces BIP-68, BIP-341, BIP-342 and the covenant opcode (BIP-119 or BIP-446) as written. That
  is true of a Bitcoin Inquisition node with those deployments active, which is what the runs here use (regtest).
  **It is not true on Bitcoin mainnet** (see LIMITS.md, item 1).

## What is not machine-checked

The step from "the leaf commits to this hash" to "only this transaction can spend through the leaf" is the meaning of
the opcodes under A2 and A4. The prover applies that meaning; it does not re-derive it. The node checks it against a
real implementation. `python -m secondstar` spends **every covenant leaf of every state** of both vaults on the node.
Each committed transaction confirms. The same transaction with its first output redirected to an attacker (same
amounts, zero fee) is refused both by the mempool and by a block built by the node's own miner. The owner then
sweeps a coin out of every state.

The prover covers the vault, not the software around it: the wallet that builds the fee child, the machine the agent
runs on, or the owner's key storage.
