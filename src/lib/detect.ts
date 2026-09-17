import bs58 from "bs58"
import type { ChainFamily } from "./types"
import { getEvmChainByKey } from "./chains"

export type QueryKind = "evm_address" | "evm_tx" | "solana_address" | "solana_tx"

export interface DetectedQuery {
  raw: string
  kind: QueryKind
  family: ChainFamily
  preferredChainKey?: string
}

const EVM_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/
const EVM_TX_RE = /^0x[a-fA-F0-9]{64}$/
const BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]+$/

function isValidBase58Pubkey(value: string): boolean {
  if (!BASE58_RE.test(value)) return false
  try {
    const decoded = bs58.decode(value)
    return decoded.length === 32
  } catch {
    return false
  }
}

function isLikelySolanaSignature(value: string): boolean {
  if (!BASE58_RE.test(value)) return false
  if (value.length < 80 || value.length > 100) return false
  try {
    const decoded = bs58.decode(value)
    // Ed25519 signatures are 64 bytes
    return decoded.length === 64
  } catch {
    return false
  }
}

export function detectQuery(
  input: string,
  chainHint?: string
): DetectedQuery {
  const raw = input.trim()
  if (!raw) {
    throw new Error("Query is empty")
  }

  const hint = chainHint?.toLowerCase()
  if (hint && hint !== "auto") {
    if (hint === "solana") {
      if (isLikelySolanaSignature(raw)) {
        return { raw, kind: "solana_tx", family: "solana", preferredChainKey: "solana" }
      }
      if (isValidBase58Pubkey(raw)) {
        return {
          raw,
          kind: "solana_address",
          family: "solana",
          preferredChainKey: "solana",
        }
      }
      throw new Error("Expected a Solana address or transaction signature")
    }

    const evm = getEvmChainByKey(hint)
    if (!evm) throw new Error(`Unknown chain: ${hint}`)

    if (EVM_TX_RE.test(raw)) {
      return {
        raw: raw.toLowerCase(),
        kind: "evm_tx",
        family: "evm",
        preferredChainKey: evm.key,
      }
    }
    if (EVM_ADDRESS_RE.test(raw)) {
      return {
        raw: raw.toLowerCase(),
        kind: "evm_address",
        family: "evm",
        preferredChainKey: evm.key,
      }
    }
    throw new Error(`Expected an EVM address or tx hash for ${evm.name}`)
  }

  if (EVM_ADDRESS_RE.test(raw)) {
    return { raw: raw.toLowerCase(), kind: "evm_address", family: "evm" }
  }
  if (EVM_TX_RE.test(raw)) {
    return { raw: raw.toLowerCase(), kind: "evm_tx", family: "evm" }
  }
  if (isLikelySolanaSignature(raw)) {
    return { raw, kind: "solana_tx", family: "solana", preferredChainKey: "solana" }
  }
  if (isValidBase58Pubkey(raw)) {
    return {
      raw,
      kind: "solana_address",
      family: "solana",
      preferredChainKey: "solana",
    }
  }

  throw new Error(
    "Could not detect query type. Paste an EVM address/tx hash or Solana address/signature."
  )
}
