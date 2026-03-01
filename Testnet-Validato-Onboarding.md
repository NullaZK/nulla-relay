# Nulla Testnet — Validator Onboarding & Token Distribution

Welcome to the Nulla testnet. This document covers everything you need to know to participate as a validator, receive testnet $NULLA tokens, and understand what comes next for the network.

---

## Registration Window

> The registration portal opens Monday, March 2 at 10:00 AM EST and closes 48 hours later on Wednesday, March 4 at 10:00 AM EST.

The dashboard is not live yet — it will become available at the opening time above. Make sure your node is running and your wallet is ready beforehand.

---

## Before You Register

You need two things set up in advance:

**1. A running validator node connected to the Nulla network**

Follow the full setup guide here → [Validator Run Guide](https://github.com/NullaZK/nulla-relay/blob/main/tutorials/validator-run.md)
Make note of your server's public IP address — you will need it during registration.

**2. The Nulla Wallet extension installed with an account created**

Follow the installation guide here → [Extension Setup Guide](https://github.com/NullaZK/NULLA-extension/blob/main/INSTALL.md) 

---

## Registration — Step by Step

When the portal opens, visit the Nulla Faucet Dashboard and complete the form:

| Field | What to Enter |
|---|---|
| **Wallet Address** | Connect your Nulla Wallet — your address will autofill |
| **Email** | Used only for distribution notifications |
| **Node IP** | The public IP address of your running validator node |

Upon submission, our system verifies that a Nulla node is live and connected at the IP address you provide. This helps prevent spam — each unique IP address and wallet can only register once.

Your data is used solely for token distribution purposes.

That's it. No further action is required after submission.

---

## Token Distribution

At the close of the 48-hour registration window, we will take a snapshot of all verified registrations and airdrop testnet $NULLA tokens directly to the recorded wallet addresses.

- Distribution is proportional across all verified validators
- The total supply for this round is fixed — the more validators that register, the smaller each individual allocation
- The exact distribution date and final amounts will be announced on our official channels prior to the airdrop

Please keep your node running and connected throughout the registration window. Nodes that go offline may affect verification status.

---

## What Comes Next

### Parachain Activation

Once the validator set is live and the relay chain is stable, the Nulla parachain will begin producing blocks. The collator will be operated by the core team during this initial phase.

With the parachain active, we will deploy a Real-World Asset (RWA) testing parachain — the first end-to-end demonstration of Nulla's architecture. It will leverage the privacy primitives provided by the ProofHub parachain (zero-knowledge proofs for on-chain asset verification) as its foundation.

---

### Nominator Faucet

We have not forgotten those who cannot run a node. A separate faucet round for nominators will follow this one — allowing anyone to participate in staking without operating infrastructure.

No one is excluded from participation.

---

## Timeline

| Phase | Description | When |
|---|---|---|
| Validator registration | Faucet portal open | **Mon Mar 2, 10 AM EST → Wed Mar 4, 10 AM EST** |
| Snapshot & airdrop | Tokens sent to verified validators | After registration closes |
| Parachain launch | Nulla parachain begins producing blocks | Following airdrop |
| RWA + ProofHub deployment | Privacy-enabled RWA testnet goes live | Following parachain launch |
| Nominator faucet | Token distribution for stakers without nodes | Following parachain launch |

---

## Stay Connected

- GitHub: <https://github.com/NullaZK>
- Telegram: <https://t.me/nullaportal>
- Twitter/X: <https://x.com/NullaNetwork>

Questions or issues? Reach out on Telegram — the team monitors it daily throughout the testnet phase.
