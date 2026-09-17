import {
  createPublicClient,
  http,
  type Hex,
  type Transaction,
  type TransactionReceipt,
} from "viem"
import {
  EVM_CHAINS,
  getEvmChainByKey,
  resolveRpcUrl,
  type EvmChainConfig,
} from "../chains"
import { decodeSelector } from "./decode"

export interface ExplorerTx {
  hash: string
  from: string
  to: string
  value: string
  input: string
  timeStamp: number
  nonce: number
  isError?: boolean
  methodId?: string
  functionName?: string
  contractAddress?: string
}

export interface TokenTransfer {
  hash: string
  from: string
  to: string
  contractAddress: string
  value: string
  tokenSymbol?: string
  tokenDecimal?: string
  timeStamp: number
}

export interface EnrichedTx {
  hash: string
  from: string
  to: string
  value: bigint
  input: string
  method: string
  timestamp: number
  nonce: number
  isContractInteraction: boolean
  receipt?: TransactionReceipt
}

function getClient(config: EvmChainConfig) {
  return createPublicClient({
    chain: config.chain,
    transport: http(resolveRpcUrl(config), { timeout: 20_000 }),
  })
}

async function etherscanGet(
  chainId: number,
  params: Record<string, string>
): Promise<unknown> {
  const key = process.env.ETHERSCAN_API_KEY
  if (!key) return null

  const url = new URL("https://api.etherscan.io/v2/api")
  url.searchParams.set("chainid", String(chainId))
  url.searchParams.set("apikey", key)
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v)
  }

  const res = await fetch(url.toString(), { next: { revalidate: 0 } })
  if (!res.ok) return null
  const json = (await res.json()) as {
    status?: string
    result?: unknown
    message?: string
  }
  if (json.status === "0" && typeof json.result === "string") {
    return null
  }
  return json.result ?? null
}

async function blockscoutGet(
  apiBase: string,
  params: Record<string, string>
): Promise<unknown> {
  const url = new URL(apiBase)
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v)
  }
  try {
    const res = await fetch(url.toString(), { next: { revalidate: 0 } })
    if (!res.ok) return null
    const json = (await res.json()) as {
      status?: string
      result?: unknown
    }
    if (json.status === "0" && typeof json.result === "string") return null
    return json.result ?? null
  } catch {
    return null
  }
}

function normalizeExplorerTxs(raw: unknown): ExplorerTx[] {
  if (!Array.isArray(raw)) return []
  return raw.map((t) => {
    const row = t as Record<string, string>
    return {
      hash: (row.hash ?? "").toLowerCase(),
      from: (row.from ?? "").toLowerCase(),
      to: (row.to ?? "").toLowerCase(),
      value: row.value ?? "0",
      input: row.input ?? "0x",
      timeStamp: Number(row.timeStamp ?? 0),
      nonce: Number(row.nonce ?? 0),
      isError: row.isError === "1",
      methodId: row.methodId,
      functionName: row.functionName,
      contractAddress: row.contractAddress?.toLowerCase(),
    }
  })
}

function normalizeTokenTransfers(raw: unknown): TokenTransfer[] {
  if (!Array.isArray(raw)) return []
  return raw.map((t) => {
    const row = t as Record<string, string>
    return {
      hash: (row.hash ?? "").toLowerCase(),
      from: (row.from ?? "").toLowerCase(),
      to: (row.to ?? "").toLowerCase(),
      contractAddress: (row.contractAddress ?? "").toLowerCase(),
      value: row.value ?? "0",
      tokenSymbol: row.tokenSymbol,
      tokenDecimal: row.tokenDecimal,
      timeStamp: Number(row.timeStamp ?? 0),
    }
  })
}

export async function fetchAddressHistory(
  config: EvmChainConfig,
  address: string,
  limit = 50
): Promise<{ txs: ExplorerTx[]; tokens: TokenTransfer[]; warnings: string[] }> {
  const warnings: string[] = []
  const addr = address.toLowerCase()
  let txs: ExplorerTx[] = []
  let tokens: TokenTransfer[] = []

  if (config.etherscanSupported) {
    const [txResult, tokenResult] = await Promise.all([
      etherscanGet(config.id, {
        module: "account",
        action: "txlist",
        address: addr,
        startblock: "0",
        endblock: "99999999",
        page: "1",
        offset: String(limit),
        sort: "desc",
      }),
      etherscanGet(config.id, {
        module: "account",
        action: "tokentx",
        address: addr,
        page: "1",
        offset: String(limit),
        sort: "desc",
      }),
    ])

    if (!txResult) {
      warnings.push(
        process.env.ETHERSCAN_API_KEY
          ? `Etherscan returned no history for ${config.name}`
          : "ETHERSCAN_API_KEY not set — EVM history may be incomplete"
      )
    } else {
      txs = normalizeExplorerTxs(txResult).slice(0, limit)
    }
    tokens = normalizeTokenTransfers(tokenResult)
  } else if (config.blockscoutApi) {
    const [txResult, tokenResult] = await Promise.all([
      blockscoutGet(config.blockscoutApi, {
        module: "account",
        action: "txlist",
        address: addr,
        page: "1",
        offset: String(limit),
        sort: "desc",
      }),
      blockscoutGet(config.blockscoutApi, {
        module: "account",
        action: "tokentx",
        address: addr,
        page: "1",
        offset: String(limit),
        sort: "desc",
      }),
    ])
    if (!txResult) {
      warnings.push(`Blockscout returned no history for ${config.name}`)
    } else {
      txs = normalizeExplorerTxs(txResult).slice(0, limit)
    }
    tokens = normalizeTokenTransfers(tokenResult)
  } else {
    warnings.push(`No explorer API configured for ${config.name}`)
  }

  return { txs, tokens, warnings }
}

export async function findTxAcrossChains(
  hash: string,
  preferredKey?: string
): Promise<{ config: EvmChainConfig; tx: Transaction; receipt: TransactionReceipt } | null> {
  const ordered = preferredKey
    ? [
        getEvmChainByKey(preferredKey)!,
        ...EVM_CHAINS.filter((c) => c.key !== preferredKey),
      ].filter(Boolean)
    : EVM_CHAINS

  for (const config of ordered) {
    try {
      const client = getClient(config)
      const tx = await client.getTransaction({ hash: hash as Hex })
      if (!tx) continue
      const receipt = await client.getTransactionReceipt({ hash: hash as Hex })
      return { config, tx, receipt }
    } catch {
      // try next chain
    }
  }
  return null
}

export async function enrichTxs(
  config: EvmChainConfig,
  explorerTxs: ExplorerTx[],
  focusHash?: string
): Promise<EnrichedTx[]> {
  const client = getClient(config)
  const slice = explorerTxs.slice(0, 40)

  const enriched: EnrichedTx[] = []
  for (const t of slice) {
    const method =
      t.functionName?.split("(")[0] ||
      decodeSelector(t.methodId ? `0x${t.methodId.replace(/^0x/, "")}` : t.input)

    let receipt: TransactionReceipt | undefined
    if (focusHash && t.hash === focusHash.toLowerCase()) {
      try {
        receipt = await client.getTransactionReceipt({ hash: t.hash as Hex })
      } catch {
        // ignore
      }
    }

    enriched.push({
      hash: t.hash,
      from: t.from,
      to: t.to,
      value: BigInt(t.value || "0"),
      input: t.input || "0x",
      method,
      timestamp: t.timeStamp,
      nonce: t.nonce,
      isContractInteraction: !!(t.input && t.input !== "0x" && t.input.length > 2),
      receipt,
    })
  }
  return enriched
}

export async function getCodeIsContract(
  config: EvmChainConfig,
  address: string
): Promise<boolean> {
  try {
    const client = getClient(config)
    const code = await client.getBytecode({ address: address as Hex })
    return !!code && code !== "0x"
  } catch {
    return false
  }
}

export async function getNativeBalance(
  config: EvmChainConfig,
  address: string
): Promise<bigint> {
  try {
    const client = getClient(config)
    return await client.getBalance({ address: address as Hex })
  } catch {
    return BigInt(0)
  }
}

export function windowAroundNonce(
  txs: ExplorerTx[],
  focusNonce: number,
  radius = 20
): ExplorerTx[] {
  const sorted = [...txs].sort((a, b) => a.nonce - b.nonce)
  const idx = sorted.findIndex((t) => t.nonce === focusNonce)
  if (idx < 0) return txs.slice(0, radius * 2)
  const start = Math.max(0, idx - radius)
  const end = Math.min(sorted.length, idx + radius + 1)
  return sorted.slice(start, end)
}
