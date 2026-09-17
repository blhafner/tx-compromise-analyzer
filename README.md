# Drain vs SRP Analyzer

Local web tool that classifies an EVM or Solana **address** or **transaction** as:

- **DRAINER** — phishing / malicious contract or program interaction
- **SRP_COMPROMISE** — seed or private-key sweeps (victim-signed simple transfers)
- **MIXED** / **LIKELY_BENIGN** / **INCONCLUSIVE**

Supported networks: Ethereum, Base, Polygon, Arbitrum, BSC, Optimism, Robinhood Chain (4663), Arc (5042), Solana.

## Setup

```bash
pnpm install
cp .env.example .env.local
# add ETHERSCAN_API_KEY and HELIUS_API_KEY (recommended)
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000).

## Env

| Variable | Purpose |
| --- | --- |
| `ETHERSCAN_API_KEY` | Etherscan API V2 history for major EVM chains |
| `HELIUS_API_KEY` / `SOLANA_RPC` | Solana RPC (public fallback is rate-limited) |
| `RPC_*` | Optional per-chain RPC overrides |

## Extending denylists

- [`data/drainer-contracts.json`](data/drainer-contracts.json) — EVM addresses
- [`data/drainer-programs.json`](data/drainer-programs.json) — Solana program IDs

ScamSniffer’s public address blacklist is fetched and cached automatically.
