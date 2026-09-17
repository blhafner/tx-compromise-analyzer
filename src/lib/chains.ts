import { defineChain, type Chain } from "viem"
import {
  mainnet,
  base,
  polygon,
  arbitrum,
  bsc,
  optimism,
} from "viem/chains"

export const robinhoodChain = defineChain({
  id: 4663,
  name: "Robinhood Chain",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: {
    default: { http: ["https://rpc.mainnet.chain.robinhood.com"] },
  },
  blockExplorers: {
    default: {
      name: "Robinhood Blockscout",
      url: "https://robinhoodchain.blockscout.com",
    },
  },
})

export const arcChain = defineChain({
  id: 5042,
  name: "Arc",
  nativeCurrency: { name: "USDC", symbol: "USDC", decimals: 18 },
  rpcUrls: {
    default: { http: ["https://rpc.mainnet.arc.io"] },
  },
  blockExplorers: {
    default: {
      name: "Arc Explorer",
      url: "https://explorer.arc.io",
    },
  },
})

export interface EvmChainConfig {
  id: number
  key: string
  name: string
  chain: Chain
  explorerUrl: string
  etherscanSupported: boolean
  blockscoutApi?: string
  defaultRpc: string
  envRpcKey: string
}

export const EVM_CHAINS: EvmChainConfig[] = [
  {
    id: 1,
    key: "ethereum",
    name: "Ethereum",
    chain: mainnet,
    explorerUrl: "https://etherscan.io",
    etherscanSupported: true,
    defaultRpc: "https://cloudflare-eth.com",
    envRpcKey: "RPC_ETHEREUM",
  },
  {
    id: 8453,
    key: "base",
    name: "Base",
    chain: base,
    explorerUrl: "https://basescan.org",
    etherscanSupported: true,
    defaultRpc: "https://mainnet.base.org",
    envRpcKey: "RPC_BASE",
  },
  {
    id: 137,
    key: "polygon",
    name: "Polygon",
    chain: polygon,
    explorerUrl: "https://polygonscan.com",
    etherscanSupported: true,
    defaultRpc: "https://polygon-rpc.com",
    envRpcKey: "RPC_POLYGON",
  },
  {
    id: 42161,
    key: "arbitrum",
    name: "Arbitrum",
    chain: arbitrum,
    explorerUrl: "https://arbiscan.io",
    etherscanSupported: true,
    defaultRpc: "https://arb1.arbitrum.io/rpc",
    envRpcKey: "RPC_ARBITRUM",
  },
  {
    id: 56,
    key: "bsc",
    name: "BNB Smart Chain",
    chain: bsc,
    explorerUrl: "https://bscscan.com",
    etherscanSupported: true,
    defaultRpc: "https://bsc-dataseed.binance.org",
    envRpcKey: "RPC_BSC",
  },
  {
    id: 10,
    key: "optimism",
    name: "Optimism",
    chain: optimism,
    explorerUrl: "https://optimistic.etherscan.io",
    etherscanSupported: true,
    defaultRpc: "https://mainnet.optimism.io",
    envRpcKey: "RPC_OPTIMISM",
  },
  {
    id: 4663,
    key: "robinhood",
    name: "Robinhood Chain",
    chain: robinhoodChain,
    explorerUrl: "https://robinhoodchain.blockscout.com",
    etherscanSupported: false,
    blockscoutApi: "https://robinhoodchain.blockscout.com/api",
    defaultRpc: "https://rpc.mainnet.chain.robinhood.com",
    envRpcKey: "RPC_ROBINHOOD",
  },
  {
    id: 5042,
    key: "arc",
    name: "Arc",
    chain: arcChain,
    explorerUrl: "https://explorer.arc.io",
    etherscanSupported: false,
    blockscoutApi: "https://explorer.arc.io/api",
    defaultRpc: "https://rpc.mainnet.arc.io",
    envRpcKey: "RPC_ARC",
  },
]

export function getEvmChainByKey(key: string): EvmChainConfig | undefined {
  return EVM_CHAINS.find(
    (c) => c.key === key.toLowerCase() || c.id.toString() === key
  )
}

export function getEvmChainById(id: number): EvmChainConfig | undefined {
  return EVM_CHAINS.find((c) => c.id === id)
}

export function resolveRpcUrl(config: EvmChainConfig): string {
  const fromEnv = process.env[config.envRpcKey]
  if (fromEnv) return fromEnv
  return config.defaultRpc
}

export function txExplorerUrl(config: EvmChainConfig, hash: string): string {
  return `${config.explorerUrl}/tx/${hash}`
}

export function addressExplorerUrl(
  config: EvmChainConfig,
  address: string
): string {
  return `${config.explorerUrl}/address/${address}`
}

export const SOLANA_EXPLORER = "https://solscan.io"

export function solanaTxUrl(sig: string): string {
  return `${SOLANA_EXPLORER}/tx/${sig}`
}

export function solanaAddressUrl(address: string): string {
  return `${SOLANA_EXPLORER}/account/${address}`
}