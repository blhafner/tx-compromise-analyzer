import {
  Connection,
  PublicKey,
  type ConfirmedSignatureInfo,
  type ParsedTransactionWithMeta,
} from "@solana/web3.js"
import { solanaTxUrl } from "../chains"

const SYSTEM_PROGRAM = "11111111111111111111111111111111"
const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
const TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
const ASSOCIATED_TOKEN = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
const COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111"
const MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
const MEMO_PROGRAM_V1 = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo"

export const KNOWN_BENIGN_PROGRAMS = new Set([
  SYSTEM_PROGRAM,
  TOKEN_PROGRAM,
  TOKEN_2022_PROGRAM,
  ASSOCIATED_TOKEN,
  COMPUTE_BUDGET,
  MEMO_PROGRAM,
  MEMO_PROGRAM_V1,
  "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", // Jupiter
  "JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB",
  "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc", // Orca
  "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", // Raydium
  "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK",
  "DCA265VkQWjRZhD7mAaWqDX5ywJN5TNT4PsEfOTYB21",
])

export interface SolanaParsedIx {
  programId: string
  program?: string
  type?: string
  info?: Record<string, unknown>
}

export interface SolanaEnrichedTx {
  signature: string
  slot: number
  blockTime: number | null
  err: unknown
  feePayer?: string
  programIds: string[]
  instructions: SolanaParsedIx[]
  hasLookupTables: boolean
  tokenTransferCount: number
  solTransferCount: number
  setAuthorityCount: number
  closeAccountCount: number
  unknownPrograms: string[]
  explorerUrl: string
}

function getConnection(): Connection {
  const helius = process.env.HELIUS_API_KEY
  const rpc =
    process.env.SOLANA_RPC ||
    (helius
      ? `https://mainnet.helius-rpc.com/?api-key=${helius}`
      : "https://api.mainnet-beta.solana.com")
  return new Connection(rpc, "confirmed")
}

function extractInstructions(
  tx: ParsedTransactionWithMeta
): SolanaParsedIx[] {
  const out: SolanaParsedIx[] = []
  const message = tx.transaction.message

  for (const ix of message.instructions) {
    if ("parsed" in ix) {
      const parsed = ix.parsed as { type?: string; info?: Record<string, unknown> }
      out.push({
        programId: ix.programId.toBase58(),
        program: ix.program,
        type: parsed?.type,
        info: parsed?.info,
      })
    } else {
      out.push({
        programId: ix.programId.toBase58(),
      })
    }
  }

  const inner = tx.meta?.innerInstructions ?? []
  for (const group of inner) {
    for (const ix of group.instructions) {
      if ("parsed" in ix) {
        const parsed = ix.parsed as { type?: string; info?: Record<string, unknown> }
        out.push({
          programId: ix.programId.toBase58(),
          program: ix.program,
          type: parsed?.type,
          info: parsed?.info,
        })
      } else {
        out.push({
          programId: ix.programId.toBase58(),
        })
      }
    }
  }

  return out
}

export function enrichParsedTx(
  signature: string,
  tx: ParsedTransactionWithMeta
): SolanaEnrichedTx {
  const instructions = extractInstructions(tx)
  const programIds = Array.from(
    new Set(instructions.map((i) => i.programId))
  )
  const unknownPrograms = programIds.filter((p) => !KNOWN_BENIGN_PROGRAMS.has(p))

  let tokenTransferCount = 0
  let solTransferCount = 0
  let setAuthorityCount = 0
  let closeAccountCount = 0

  for (const ix of instructions) {
    const t = ix.type ?? ""
    if (
      t === "transfer" ||
      t === "transferChecked" ||
      t === "transferCheckedWithFee"
    ) {
      if (
        ix.programId === TOKEN_PROGRAM ||
        ix.programId === TOKEN_2022_PROGRAM
      ) {
        tokenTransferCount++
      } else if (ix.programId === SYSTEM_PROGRAM) {
        solTransferCount++
      }
    }
    if (t === "setAuthority" || t === "approve" || t === "approveChecked") {
      setAuthorityCount++
    }
    if (t === "closeAccount") {
      closeAccountCount++
    }
  }

  const hasLookupTables =
    // v0 messages with ALTs
    Boolean(
      (tx.transaction.message as { addressTableLookups?: unknown[] })
        .addressTableLookups?.length
    )

  const feePayer = tx.transaction.message.accountKeys[0]?.pubkey?.toBase58?.()
    ?? (typeof tx.transaction.message.accountKeys[0]?.pubkey === "string"
      ? String(tx.transaction.message.accountKeys[0].pubkey)
      : undefined)

  return {
    signature,
    slot: tx.slot,
    blockTime: tx.blockTime ?? null,
    err: tx.meta?.err ?? null,
    feePayer,
    programIds,
    instructions,
    hasLookupTables,
    tokenTransferCount,
    solTransferCount,
    setAuthorityCount,
    closeAccountCount,
    unknownPrograms,
    explorerUrl: solanaTxUrl(signature),
  }
}

export async function fetchSolanaTransaction(
  signature: string
): Promise<{ tx: SolanaEnrichedTx; warnings: string[] } | null> {
  const warnings: string[] = []
  if (!process.env.HELIUS_API_KEY && !process.env.SOLANA_RPC) {
    warnings.push(
      "Using public Solana RPC — rate limits may cause incomplete results. Set HELIUS_API_KEY or SOLANA_RPC."
    )
  }

  const connection = getConnection()
  const raw = await connection.getParsedTransaction(signature, {
    maxSupportedTransactionVersion: 0,
    commitment: "confirmed",
  })
  if (!raw) return null
  return { tx: enrichParsedTx(signature, raw), warnings }
}

export async function fetchSolanaAddressActivity(
  address: string,
  limit = 40
): Promise<{
  txs: SolanaEnrichedTx[]
  signatures: ConfirmedSignatureInfo[]
  warnings: string[]
}> {
  const warnings: string[] = []
  if (!process.env.HELIUS_API_KEY && !process.env.SOLANA_RPC) {
    warnings.push(
      "Using public Solana RPC — rate limits may cause incomplete results. Set HELIUS_API_KEY or SOLANA_RPC."
    )
  }

  const connection = getConnection()
  const pubkey = new PublicKey(address)
  const signatures = await connection.getSignaturesForAddress(pubkey, {
    limit,
  })

  const txs: SolanaEnrichedTx[] = []
  // Batch in small chunks to avoid rate limits
  const chunkSize = 8
  for (let i = 0; i < signatures.length; i += chunkSize) {
    const chunk = signatures.slice(i, i + chunkSize)
    const results = await Promise.all(
      chunk.map(async (sig) => {
        try {
          const raw = await connection.getParsedTransaction(sig.signature, {
            maxSupportedTransactionVersion: 0,
            commitment: "confirmed",
          })
          if (!raw) return null
          return enrichParsedTx(sig.signature, raw)
        } catch {
          return null
        }
      })
    )
    for (const r of results) {
      if (r) txs.push(r)
    }
  }

  return { txs, signatures, warnings }
}

export async function windowAroundSignature(
  address: string,
  focusSignature: string,
  radius = 20
): Promise<{ txs: SolanaEnrichedTx[]; warnings: string[] }> {
  const { txs, signatures, warnings } = await fetchSolanaAddressActivity(
    address,
    radius * 3
  )
  const idx = signatures.findIndex((s) => s.signature === focusSignature)
  if (idx < 0) return { txs, warnings }

  const start = Math.max(0, idx - radius)
  const end = Math.min(signatures.length, idx + radius + 1)
  const windowSigs = new Set(
    signatures.slice(start, end).map((s) => s.signature)
  )
  return {
    txs: txs.filter((t) => windowSigs.has(t.signature)),
    warnings,
  }
}

export { SYSTEM_PROGRAM, TOKEN_PROGRAM }
