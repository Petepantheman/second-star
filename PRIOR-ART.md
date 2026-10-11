# Prior art

The idea that an agent's spending limit should live in the coins, not in software, is not new, and other chains got
there first. What this repo adds is narrow. It is a working allowance built twice, once on each of two Bitcoin
covenant proposals (CTV and TEMPLATEHASH), in which the agent holds **no key** and the payees are written into the
script. It comes with a prover that checks every state of the vault from its bytes. I opened every link below on
2026-10-11.

## Agent allowances enforced by the chain, on other chains

- **AgentLeash (Bitcoin Cash)**, [ttimesai-star/agentleash-bch](https://github.com/ttimesai-star/agentleash-bch),
  created 2026-10-10. A CashScript covenant with an NFT state that enforces a per-window limit, three allow-listed
  payees and a fee cap. The agent signs its own payments; the owner can withdraw at any time. It has 94 tests and a
  chipnet run, and no proofs. Bitcoin Cash has the introspection opcodes this needs today.
- **BRC-172 (BSV)**, [Giving an AI Agent Control of a Delivery Vehicle Without Giving It a Wallet](https://github.com/bsv-blockchain/BRCs/blob/master/state-machines/0172.md).
  A covenant that enforces its own successor state, so the agent has "control without custody": at most a
  credential that advances the covenant and cannot direct value anywhere. It is the closest keyless relative of
  Second Star. Its scope note says payee-bound and rate-bound covenants "are separate proposals", and that capping
  value per unit of time is unavailable because "a covenant has no clock but `nLockTime`". On Bitcoin, BIP-68 relative
  timelocks give the covenant that clock.
- **BRC-204 (BSV)**, [Agent Allowances](https://github.com/bsv-blockchain/BRCs/blob/master/wallet/0204.md), draft. An
  allowance held under a two-branch locking script: the agent spends with its own key and the owner can sweep.
- **Noether (Cardano)**, [ardey26/noether](https://github.com/ardey26/noether), preprod MVP. An on-chain validator
  checks a window cap, a per-transaction cap and a destination allowlist. The language-model process holds no key;
  a separate signer process does.

## Agent limits enforced off-chain

- **TEE-enforced batches**, [Letting Untrusted LLMs Sign Bitcoin Batches](https://delvingbitcoin.org/t/letting-untrusted-llms-sign-bitcoin-batches-mcp-bridge-tee-enforced-25-tx-daisy-chains/2410)
  (Delving Bitcoin, 2026-04-11). An enclave checks each transaction before signing; the allowance leaf is a
  placeholder for future Simplicity code.
- **Co-signer spending policies**, [BIP draft](https://delvingbitcoin.org/t/bip-draft-co-signer-spending-policies/2955)
  (Delving Bitcoin, 2026-10-10). It standardises what a co-signer enforces and says "anything script can enforce is
  required to be in script". Second Star is a case where all of it is in script.
- Wallet-side budgets in Lightning tooling (macaroon spend caps, Nostr Wallet Connect budgets) are software limits:
  whoever holds the credential and the node can lift them.

## Bitcoin vaults with templates

- **simple-ctv-vault**, [jamesob/simple-ctv-vault](https://github.com/jamesob/simple-ctv-vault) (2022). The
  original CTV vault demo: unvault to a delay, then a hot key spends, or the owner claws back to cold.
- **MCCV**, [LNHANCE-Expedition/mccv](https://github.com/LNHANCE-Expedition/mccv) ("More Complicated CTV Vault"),
  announced as v0.1.0 on [Delving Bitcoin](https://delvingbitcoin.org/t/ctv-only-vault-concept-v0-1-0-release/2539)
  (2026-05-28). This is the closest Bitcoin relative. It precomputes a large CTV transaction tree with
  consensus-enforced velocity control: withdrawals come in fixed increments, behind a relative timelock that scales
  with the amount. Its protocol notes require ephemeral-anchor policy for its zero-fee transactions. Hot keys authorize
  its operations, and a matured withdrawal is spendable by the hot wallet, anywhere. Second Star keeps the rate limit,
  removes the spender's key, and writes the payees into the script.
- **Comparing Bitcoin Covenant Proposals for Vaults**, [Delving Bitcoin](https://delvingbitcoin.org/t/comparing-bitcoin-covenant-proposals-for-vaults/2877)
  (2026-09-04). It concludes that "CTV is suited to simple vaults with precomputed outputs" and that CCV fits
  trigger-time choice of address. Second Star's fixed menu is exactly that precomputed-output limit.

## Checking covenant vaults by machine

- **Covenant vault research**, [PraneethGunas/covenant-vault-research](https://github.com/PraneethGunas/covenant-vault-research)
  (branch `alloy-count-fix`, `formalization/alloy/`). Alloy models of CTV, CCV and CAT+CSFS vaults, checked by
  bounded model checking on an abstract model.
- **Analyzing simple vault covenant with Alloy**, [Delving Bitcoin](https://delvingbitcoin.org/t/analyzing-simple-vault-covenant-with-alloy/819) (2024-04-19).
- **Bitcoin covenants unchained**, Bartoletti, Lande and Zunino, [arXiv:2006.03918](https://arxiv.org/abs/2006.03918).
  A formal model of covenants and how to specify contracts with them.

Second Star's prover differs in kind, not just in scope. It does not model the vault; it reads the real leaf scripts and
templates, rebuilds every address, and checks every reachable state of that specific vault (see PROOF.md).

## Specifications

[BIP-119](https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki) (CTV) ·
[BIP-446](https://github.com/bitcoin/bips/blob/master/bip-0446.md) (TEMPLATEHASH) ·
[BIP-448](https://github.com/bitcoin/bips/blob/master/bip-0448.md) (TEMPLATEHASH + CSFS + INTERNALKEY) ·
[BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) (Taproot) ·
[BIP-68](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki) (relative timelocks) ·
[Bitcoin Inquisition](https://github.com/bitcoin-inquisition/bitcoin) (the node these runs use).
