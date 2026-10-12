# Second Star on Lightning

**The vault has a speed limit. A Lightning wallet does not.** The covenant rations a coin only until it leaves the vault.
After that, it is ordinary money. So the question this layer answers is: once the allowance reaches an AI agent's
Lightning wallet, what can a hijacked agent still take, and how do you shrink that?

```
python -m secondstar.lightning_run --bitcoind /path/to/bitcoind --lnd /path/to/lnd           # CTV
python -m secondstar.lightning_run --bitcoind /path/to/bitcoind --lnd /path/to/lnd --opcode templatehash
```

One command starts a private regtest node and five LND 0.21 nodes: the agent, a swap provider (who also routes), a shop
selling a pay-per-call API, Hook, and a small node on the owner's side. Hook takes over the agent's machine. The vault
has the same parameters as in the [README](README.md) (1,000,000 sats, 100,000 per period, a 3-block wait); its menu is
one swap lock per payment.

## Three ways to get the allowance into Lightning

| | where each tranche goes | who can take a tranche once Hook has the agent's machine | measured |
|---|---|---|---|
| **plain wallet** | the agent's own on-chain address | Hook alone | Hook +86,182 sats on-chain (LND kept 10,000 back as its anchor fee reserve; 3,818 went to the sweep fee) |
| **naive swap** | a swap lock; the agent's node holds the secret | Hook plus a dishonest provider | Hook read the secret from the node; provider +99,500, agent +0 |
| **held swap** | a swap lock; the owner's node holds the hold invoice, the owner's signer keeps the secret | not Hook, even with a dishonest provider, before it lands: there is no secret on the agent's machine to hand over | every refill +99,000; every secret on the agent's machine tried against the lock, all refused |

In every design, Hook can spend whatever has already reached the agent's Lightning wallet. In the held swap 248,000
came in over two periods (two refills of 99,000 and a 50,000 tip) and Hook took 222,993 of it. The agent had spent
5,000 on API calls; the other 20,007 is what stayed in the wallet (the run drains it down to 20,000) plus a few sats of
routing fees.

### The swap lock

Each payment goes to its own Taproot output. Its internal key is the BIP-341 NUMS point, which nobody knows the secret
of, so short of a quantum computer (see [LIMITS.md](LIMITS.md), item 12) only its two leaves can spend it:

```
claim   OP_SHA256 <hash> OP_EQUALVERIFY <provider key> OP_CHECKSIG
refund  <144> OP_CHECKSEQUENCEVERIFY OP_DROP <owner key> OP_CHECKSIG
```

As long as whoever keeps the secret behind `<hash>` keeps it safe, the provider can learn it only by paying a Lightning
invoice with that payment hash, so it can claim the on-chain tranche only after its Lightning payment settles. This is the
idea behind submarine swaps (Loop In, Boltz). What is new here is that a covenant fixes a whole schedule of these locks
in advance. The prover checks that every lock has its own payment hash and that no lock can be paid twice on any path,
so within one funding of the vault, one Lightning payment can never unlock more than one tranche.

### Why "held", and why on the owner's node

In the naive version the agent's node creates an ordinary invoice, so it holds the secret, and anything with access to
the node can read it. The run shows Hook doing exactly that and handing it to a dishonest provider, who then claims the
tranche without paying.

In the held version a small Lightning node on the owner's side creates a **hold invoice** for each lock. It is given
only the payment hash; the owner's signer keeps the secrets. When the provider pays, the payment is held at the owner's
node. The signer reads the owner's own node, and once the payment is held there for the right amount, it settles. That
hands the secret to the provider, and the owner's node then pays the agent's node 99,000 sats by its fixed public key
(keysend). The swap's hash and secret never touch the agent's machine, so taking over that whole machine gives Hook no
secret to sell to a provider. The run hands every payment secret on the agent's node to a dishonest provider; none opens
the lock.

An earlier version kept the hold invoice on the agent's node. A reviewer pointed out that the signer then had to ask
the agent's node whether the payment had arrived, and Hook, controlling that machine, could lie. Moving the invoice to
the owner's node removes that.

### The provider's deadline

The provider must be able to claim before the owner's refund opens; otherwise the claim and the refund could both be
valid at once. It follows two rules:

1. It refuses an invoice that could not fit even on a direct channel: the tip, plus the invoice's final CLTV delta
   (40), plus LND's 3-block padding, plus a 12-block margin, must come before the refund opens (the lock's
   confirmation height plus 144).
2. It pays with a CLTV cap (`--cltv_limit`), so LND will not pick a route whose advertised delay, every hop included,
   runs into the 12-block margin before the refund opens. The real expiry is checked separately, below.

Before anything settles, the provider reads the real expiry of its outgoing payment from its own channel. If it ever
came out too late anyway, the swap is called off: the owner's node cancels the invoice and the payment goes back to the
provider. On the run's direct channel the cap holds, so a unit test covers that branch with a stand-in node. The run also
includes an invoice that breaks rule 1 (final CLTV delta 140), and the provider refuses to pay it.

## What the run checks

Every line is checked against the nodes; the run exits non-zero if any fails. Both covenant versions pass.

- The prover returns `PROVED` for the swap vault, and also proves from the bytes that every menu address is exactly one
  of the listed swap locks, each with its own payment hash, each refunding to the owner's key, and none payable twice
  on any path.
- No refill before the wait. During the wait the agent keeps paying over Lightning: five paid API calls and a drain.
- Each held refill: the owner's node settles only once the provider's payment is held there, and the agent's Lightning
  balance goes up by exactly 99,000 sats (100,000 minus a 1,000-sat swap fee), no matter how much the agent has spent.
- After each refill, the swap's hash and secret are nowhere on the agent's node.
- With the agent's whole machine in Hook's hands, every payment secret on it (invoices, keysend receipts, payments) is
  handed to a dishonest provider; none opens the lock. Hook cannot open it with a guess either, cannot use the refund
  path before its delay, and cannot use it after the delay, because it needs the owner's key.
- The provider's payment expires at least 12 blocks before the refund opens, read from its own channel. An invoice that
  breaks the deadline is refused.
- A paid API in the L402 style: five calls paid over Lightning and served. An honest client's software cap refuses a
  call above its cap.
- A 50,000-sat tip from the shop reaches the agent while the vault coin does not move. The vault limits what leaves
  the coin, not what the agent can receive.
- Hook drains what the agent's Lightning wallet holds, cannot release the next tranche early, and cannot make the
  vault pay him after the wait.
- The owner sweeps the rest of the vault home (+799,500).
- After the refused invoice, the owner waits out the 144 blocks and takes the tranche back (+99,500). Hook cannot use
  the refund path even then.

## Limits of this layer

- **The owner's side is now a trusted, online part.** The owner's node must be online at refill time and needs
  liquidity: inbound for the provider's payments, outbound to pay the agent (in the run it pays through the provider's
  channel, so the provider also earns its routing fee). The signer trusts that node, so whoever takes over the
  owner's machine can get the secrets and, with a dishonest provider, take the refills. As long as the owner's cold
  key is not on that machine, they still cannot take the vault: its leaves pay only the scheduled swap locks, and
  only the cold key can sweep it (short of the quantum attack in [LIMITS.md](LIMITS.md), item 12). Keep the owner's
  node on a different machine from the agent.
- **Stealing a refill needs two parties.** A swap lock's claim path needs the provider's key, and only the owner can
  use its refund path (both short of the quantum attack in [LIMITS.md](LIMITS.md), item 12). In the naive
  design, Hook with access to the agent's node plus a dishonest provider is enough. In the held design they need the
  owner's machine instead. Choose the provider the way you choose the menu: it is part of the blast radius.
- **Fund each swap vault exactly once.** Each claim puts its secret on-chain. A second deposit to an already-used
  vault reuses those hashes, and the run shows the provider claiming it without paying (+99,500).
- **The refund can be slow.** If the provider disappears, the owner waits 144 blocks per tranche.
- **Hot balance is hot.** Whatever has reached the agent's Lightning wallet, refills plus anything paid to it from
  outside, can be spent by whoever controls the agent's node. The covenant limits how fast new money arrives. It does
  not protect money that has already arrived.
- **Not on mainnet,** for the same reason as the vault (see [LIMITS.md](LIMITS.md)).

## Prior art for this layer

Covenant-built channels (BIP-119 batched channel opens, channel factories, timeout trees, Ark) and software budgets for
agents (scoped macaroons and `--max-cost` in Lightning Labs' agent tools, NWC budgets) both exist. On-chain-to-Lightning
swaps ship today: [Loop In](https://github.com/lightninglabs/loop/blob/master/docs/architecture.md) and
[Boltz submarine swaps](https://github.com/BoltzExchange/boltz-backend/blob/master/docs/lifecycle.md) use the same
idea of a claim that needs the payment's secret and a refund after a timeout. Boltz uses covenants on Liquid for
reverse-swap claims. Hold invoices and refunds to whoever funded a swap are standard. A Bitcoin covenant that fixes a
whole schedule of swaps into an agent's Lightning balance in advance was not found (searched 2026-10-11); the schedule
is the new part.
