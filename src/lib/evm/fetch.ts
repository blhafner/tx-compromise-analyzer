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
import { parseEip7702Delegation } from "./eip7702"

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
  txType?: number | string
  /** Delegates from EIP-7702 authorization_list (if present) */
  authorizationDelegates?: string[]
  /** Address shows active 7702 proxy in explorer metadata */
  fromIsEip7702Proxy?: boolean
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

function getClient(config: EvmChainConfig, rpcOverride?: string) {
  return createPublicClient({
    chain: config.chain,
    transport: http(rpcOverride ?? resolveRpcUrl(config), { timeout: 20_000 }),
  })
}

interface EtherscanResponse {
  ok: boolean
  result: unknown
  error?: string
}

async function etherscanGet(
  chainId: number,
  params: Record<string, string>
): Promise<EtherscanResponse> {
  const key = process.env.ETHERSCAN_API_KEY
  if (!key) {
    return { ok: false, result: null, error: "ETHERSCAN_API_KEY not set" }
  }

  const url = new URL("https://api.etherscan.io/v2/api")
  url.searchParams.set("chainid", String(chainId))
  url.searchParams.set("apikey", key)
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v)
  }

  try {
    const res = await fetch(url.toString(), { next: { revalidate: 0 } })
    if (!res.ok) {
      return { ok: false, result: null, error: `Etherscan HTTP ${res.status}` }
    }
    const json = (await res.json()) as {
      status?: string
      result?: unknown
      message?: string
    }
    if (json.status === "0") {
      const msg =
        typeof json.result === "string"
          ? json.result
          : json.message || "Etherscan error"
      // Empty result is not always an error
      if (msg === "No transactions found" || msg === "No records found") {
        return { ok: true, result: [] }
      }
      return { ok: false, result: null, error: msg }
    }
    return { ok: true, result: json.result ?? null }
  } catch (err) {
    return {
      ok: false,
      result: null,
      error: err instanceof Error ? err.message : "Etherscan request failed",
    }
  }
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
    const res = await fetch(url.toString(), {
      next: { revalidate: 0 },
      headers: { Accept: "application/json", "User-Agent": "tx-compromise-analyzer" },
    })
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

function addrHash(value: unknown): string {
  if (!value) return ""
  if (typeof value === "string") return value.toLowerCase()
  if (typeof value === "object" && value !== null && "hash" in value) {
    return String((value as { hash: string }).hash || "").toLowerCase()
  }
  return ""
}

function parseIsoTimestamp(value: unknown): number {
  if (typeof value === "number") return value
  if (typeof value === "string") {
    if (/^\d+$/.test(value)) return Number(value)
    const ms = Date.parse(value)
    return Number.isFinite(ms) ? Math.floor(ms / 1000) : 0
  }
  return 0
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

function normalizeBlockscoutV2Txs(raw: unknown): ExplorerTx[] {
  if (!raw || typeof raw !== "object") return []
  const items = (raw as { items?: unknown[] }).items
  if (!Array.isArray(items)) return []

  return items.map((item) => {
    const row = item as Record<string, unknown>
    const fromObj = row.from as
      | { hash?: string; proxy_type?: string; implementations?: { address_hash?: string }[] }
      | undefined
    const authList = Array.isArray(row.authorization_list)
      ? (row.authorization_list as { address?: string; authority?: string }[])
      : []
    const method =
      typeof row.method === "string"
        ? row.method
        : typeof (row.decoded_input as { method_call?: string } | null)?.method_call ===
            "string"
          ? (row.decoded_input as { method_call: string }).method_call
          : undefined

    return {
      hash: String(row.hash ?? "").toLowerCase(),
      from: addrHash(row.from),
      to: addrHash(row.to),
      value: String(row.value ?? "0"),
      input: String(row.raw_input ?? row.input ?? "0x"),
      timeStamp: parseIsoTimestamp(row.timestamp),
      nonce: Number(row.nonce ?? 0),
      isError: row.status === "error" || row.result === "error",
      methodId:
        typeof method === "string" && method.startsWith("0x")
          ? method.slice(0, 10)
          : undefined,
      functionName: method && !method.startsWith("0x") ? method : undefined,
      txType: row.type as number | string | undefined,
      authorizationDelegates: authList
        .map((a) => (a.address || a.authority || "").toLowerCase())
        .filter(Boolean),
      fromIsEip7702Proxy: fromObj?.proxy_type === "eip7702",
    }
  })
}

function normalizeBlockscoutV2Tokens(raw: unknown): TokenTransfer[] {
  if (!raw || typeof raw !== "object") return []
  const items = (raw as { items?: unknown[] }).items
  if (!Array.isArray(items)) return []

  return items.map((item) => {
    const row = item as Record<string, unknown>
    const token = (row.token || {}) as {
      address_hash?: string
      address?: string
      symbol?: string
      decimals?: string
    }
    const total = (row.total || {}) as { value?: string }
    return {
      hash: String(row.transaction_hash ?? row.tx_hash ?? "").toLowerCase(),
      from: addrHash(row.from),
      to: addrHash(row.to),
      contractAddress: (
        token.address_hash ||
        token.address ||
        ""
      ).toLowerCase(),
      value: String(total.value ?? row.value ?? "0"),
      tokenSymbol: token.symbol,
      tokenDecimal: token.decimals,
      timeStamp: parseIsoTimestamp(row.timestamp),
    }
  })
}

async function fetchBlockscoutV2History(
  baseUrl: string,
  address: string,
  limit: number
): Promise<{ txs: ExplorerTx[]; tokens: TokenTransfer[] } | null> {
  try {
    const headers = {
      Accept: "application/json",
      "User-Agent": "tx-compromise-analyzer",
    }
    const [txRes, tokenRes] = await Promise.all([
      fetch(`${baseUrl}/api/v2/addresses/${address}/transactions`, {
        headers,
        next: { revalidate: 0 },
      }),
      fetch(`${baseUrl}/api/v2/addresses/${address}/token-transfers`, {
        headers,
        next: { revalidate: 0 },
      }),
    ])

    if (!txRes.ok) return null
    const txJson = await txRes.json()
    const tokenJson = tokenRes.ok ? await tokenRes.json() : { items: [] }

    return {
      txs: normalizeBlockscoutV2Txs(txJson).slice(0, limit),
      tokens: normalizeBlockscoutV2Tokens(tokenJson).slice(0, limit),
    }
  } catch {
    return null
  }
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

    if (txResult.ok) {
      txs = normalizeExplorerTxs(txResult.result).slice(0, limit)
      tokens = normalizeTokenTransfers(tokenResult.ok ? tokenResult.result : null)
    } else if (txResult.error) {
      const planBlocked =
        /free api access is not supported|upgrade your api plan/i.test(
          txResult.error
        )
      warnings.push(
        planBlocked
          ? `Etherscan free plan does not cover ${config.name}; using Blockscout fallback`
          : `Etherscan unavailable for ${config.name}: ${txResult.error}`
      )
    }
  }

  if (txs.length === 0 && config.blockscoutV2) {
    const v2 = await fetchBlockscoutV2History(config.blockscoutV2, addr, limit)
    if (v2 && v2.txs.length > 0) {
      txs = v2.txs
      if (tokens.length === 0) tokens = v2.tokens
      warnings.push(`History loaded via Blockscout for ${config.name}`)
    } else if (txs.length === 0 && !config.blockscoutApi) {
      warnings.push(`Blockscout returned no history for ${config.name}`)
    }
  }

  if (txs.length === 0 && config.blockscoutApi) {
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
    if (txResult) {
      txs = normalizeExplorerTxs(txResult).slice(0, limit)
      tokens = normalizeTokenTransfers(tokenResult)
    } else if (txs.length === 0) {
      warnings.push(`No explorer history for ${config.name}`)
    }
  }

  if (txs.length === 0 && !config.etherscanSupported && !config.blockscoutApi && !config.blockscoutV2) {
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
      // Prefer official public RPC if env RPC fails
      if (resolveRpcUrl(config) !== config.defaultRpc) {
        try {
          const client = getClient(config, config.defaultRpc)
          const tx = await client.getTransaction({ hash: hash as Hex })
          if (!tx) continue
          const receipt = await client.getTransactionReceipt({
            hash: hash as Hex,
          })
          return { config, tx, receipt }
        } catch {
          // try next chain
        }
      }
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

export async function getAccountCode(
  config: EvmChainConfig,
  address: string
): Promise<string | undefined> {
  const urls = Array.from(
    new Set([resolveRpcUrl(config), config.defaultRpc].filter(Boolean))
  )
  for (const url of urls) {
    try {
      const client = getClient(config, url)
      const code = await client.getBytecode({ address: address as Hex })
      if (code !== undefined) return code
    } catch {
      // try next
    }
  }
  return undefined
}

export async function getEip7702Delegation(
  config: EvmChainConfig,
  address: string
): Promise<string | undefined> {
  const code = await getAccountCode(config, address)
  return parseEip7702Delegation(code)
}

export async function getCodeIsContract(
  config: EvmChainConfig,
  address: string
): Promise<boolean> {
  try {
    const code = await getAccountCode(config, address)
    return !!code && code !== "0x" && !parseEip7702Delegation(code)
  } catch {
    return false
  }
}

export async function getNativeBalance(
  config: EvmChainConfig,
  address: string
): Promise<bigint> {
  const urls = Array.from(
    new Set([resolveRpcUrl(config), config.defaultRpc].filter(Boolean))
  )
  for (const url of urls) {
    try {
      const client = getClient(config, url)
      return await client.getBalance({ address: address as Hex })
    } catch {
      // try next
    }
  }
  return BigInt(0)
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
