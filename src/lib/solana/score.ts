import type { EvidenceItem, TimelineTx, Verdict } from "../types"
import type { LabelHit } from "../types"
import type { SolanaEnrichedTx } from "./fetch"
import { KNOWN_BENIGN_PROGRAMS, SYSTEM_PROGRAM } from "./fetch"
import { solanaTxUrl } from "../chains"

export interface SolanaScoreInput {
  victim: string
  txs: SolanaEnrichedTx[]
  labels: LabelHit[]
  focus?: SolanaEnrichedTx
}

export interface SolanaScoreResult {
  verdict: Verdict
  confidence: number
  evidence: EvidenceItem[]
  timeline: TimelineTx[]
  summary: string
}

function scoreToVerdict(
  drainer: number,
  srp: number,
  benign: number
): { verdict: Verdict; confidence: number } {
  const total = drainer + srp + benign
  if (total === 0) return { verdict: "INCONCLUSIVE", confidence: 15 }

  const max = Math.max(drainer, srp, benign)
  const confidence = Math.min(95, Math.round((max / total) * 100))

  if (drainer >= 8 && srp >= 8) {
    return { verdict: "MIXED", confidence: Math.min(90, confidence) }
  }
  if (drainer >= srp && drainer >= benign && drainer >= 6) {
    return { verdict: "DRAINER", confidence }
  }
  if (srp >= drainer && srp >= benign && srp >= 6) {
    return { verdict: "SRP_COMPROMISE", confidence }
  }
  if (benign > drainer && benign > srp && benign >= 4) {
    return { verdict: "LIKELY_BENIGN", confidence: Math.min(70, confidence) }
  }
  if (drainer > 0 && srp > 0) {
    return { verdict: "MIXED", confidence: Math.max(40, confidence - 10) }
  }
  if (drainer > srp && drainer > 0) {
    return { verdict: "DRAINER", confidence: Math.max(35, confidence - 15) }
  }
  if (srp > drainer && srp > 0) {
    return {
      verdict: "SRP_COMPROMISE",
      confidence: Math.max(35, confidence - 15),
    }
  }
  return { verdict: "INCONCLUSIVE", confidence: 25 }
}

export function scoreSolana(input: SolanaScoreInput): SolanaScoreResult {
  const { victim, txs, labels, focus } = input
  const evidence: EvidenceItem[] = []
  let drainer = 0
  let srp = 0
  let benign = 0

  const successful = txs.filter((t) => !t.err)

  for (const hit of labels) {
    evidence.push({
      id: `label-${hit.address}`,
      label: "Known drainer program",
      detail: `Program ${hit.address} flagged by ${hit.source}`,
      polarity: "drainer",
      weight: 28,
    })
    drainer += 28
  }

  let unknownProgramHits = 0
  let batchDrainSigs = 0
  let setAuthorityTotal = 0
  let closeAccountTotal = 0
  let onlySystemToken = 0
  let solTransferTotal = 0
  let tokenTransferTotal = 0

  for (const t of successful) {
    if (t.unknownPrograms.length > 0) {
      unknownProgramHits++
      // weight heavier if many transfers in same sig
      if (t.tokenTransferCount + t.solTransferCount >= 3) {
        batchDrainSigs++
      }
    }
    setAuthorityTotal += t.setAuthorityCount
    closeAccountTotal += t.closeAccountCount
    solTransferTotal += t.solTransferCount
    tokenTransferTotal += t.tokenTransferCount

    const onlyKnown = t.programIds.every((p) => KNOWN_BENIGN_PROGRAMS.has(p))
    if (
      onlyKnown &&
      (t.solTransferCount > 0 || t.tokenTransferCount > 0) &&
      t.unknownPrograms.length === 0
    ) {
      onlySystemToken++
    }
  }

  if (focus) {
    if (focus.unknownPrograms.length > 0) {
      evidence.push({
        id: "focus-unknown-program",
        label: "Focus tx uses unknown program(s)",
        detail: focus.unknownPrograms.slice(0, 4).join(", "),
        polarity: "drainer",
        weight: 18,
      })
      drainer += 18
    }
    if (focus.tokenTransferCount + focus.solTransferCount >= 4) {
      evidence.push({
        id: "focus-batch-transfers",
        label: "Many transfers in one signature",
        detail: `${focus.tokenTransferCount} token + ${focus.solTransferCount} SOL transfers — common Solana drainer batch pattern`,
        polarity: "drainer",
        weight: 16,
      })
      drainer += 16
    }
    if (focus.hasLookupTables) {
      evidence.push({
        id: "focus-alt",
        label: "Address Lookup Tables used",
        detail: "ALTs can hide destination accounts in phishing txs",
        polarity: "drainer",
        weight: 8,
      })
      drainer += 8
    }
    if (focus.setAuthorityCount > 0) {
      evidence.push({
        id: "focus-set-authority",
        label: "Authority / delegate change",
        detail: `${focus.setAuthorityCount} setAuthority/approve instruction(s)`,
        polarity: "drainer",
        weight: 14,
      })
      drainer += 14
    }
  }

  if (unknownProgramHits > 0) {
    evidence.push({
      id: "unknown-programs",
      label: "Non-standard program invocations",
      detail: `${unknownProgramHits} signature(s) invoke programs outside the known System/Token/DEX set`,
      polarity: "drainer",
      weight: 12 + Math.min(unknownProgramHits * 2, 10),
    })
    drainer += 12 + Math.min(unknownProgramHits * 2, 10)
  }

  if (batchDrainSigs > 0) {
    evidence.push({
      id: "batch-drains",
      label: "Batch asset moves via custom program",
      detail: `${batchDrainSigs} signature(s) combine unknown programs with ≥3 transfers`,
      polarity: "drainer",
      weight: 14,
    })
    drainer += 14
  }

  if (setAuthorityTotal > 0 && !focus) {
    evidence.push({
      id: "set-authority-window",
      label: "Token authority changes in window",
      detail: `${setAuthorityTotal} setAuthority/approve instruction(s)`,
      polarity: "drainer",
      weight: 10,
    })
    drainer += 10
  }

  // SRP: only system/token, multiple sweeps, close accounts, no mystery programs
  if (
    onlySystemToken >= 2 &&
    unknownProgramHits === 0 &&
    batchDrainSigs === 0 &&
    (solTransferTotal + tokenTransferTotal) >= 2
  ) {
    evidence.push({
      id: "system-token-only-sweeps",
      label: "System/Token-only sweeps",
      detail: `${onlySystemToken} victim-signed transfer signature(s) with no custom programs — typical SRP on Solana`,
      polarity: "srp",
      weight: 18,
    })
    srp += 18
  }

  if (closeAccountTotal > 0 && unknownProgramHits === 0) {
    evidence.push({
      id: "close-accounts",
      label: "Token accounts closed (rent reclaim)",
      detail: `${closeAccountTotal} closeAccount instruction(s) — common after full wallet emptying`,
      polarity: "srp",
      weight: 8,
    })
    srp += 8
  }

  // Gas drip analogue: inbound SOL then outbound — approximate via fee payer txs that only transfer
  if (
    successful.length >= 3 &&
    unknownProgramHits === 0 &&
    solTransferTotal >= 2 &&
    tokenTransferTotal >= 1
  ) {
    evidence.push({
      id: "multi-asset-empty",
      label: "Multi-asset emptying via native transfers",
      detail: `SOL transfers: ${solTransferTotal}, token transfers: ${tokenTransferTotal}, no custom drain programs`,
      polarity: "srp",
      weight: 12,
    })
    srp += 12
  }

  if (
    successful.length <= 2 &&
    unknownProgramHits === 0 &&
    setAuthorityTotal === 0 &&
    batchDrainSigs === 0
  ) {
    evidence.push({
      id: "low-activity",
      label: "Low / ordinary activity",
      detail: "No custom programs, authority changes, or batch drains in the window",
      polarity: "benign",
      weight: 8,
    })
    benign += 8
  }

  // Jupiter-only etc
  const jupiterOnly = successful.filter((t) =>
    t.programIds.some(
      (p) =>
        p.startsWith("JUP") ||
        p === "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8"
    )
  )
  if (
    jupiterOnly.length > 0 &&
    unknownProgramHits === 0 &&
    setAuthorityTotal === 0
  ) {
    evidence.push({
      id: "known-dex",
      label: "Known DEX interaction",
      detail: `${jupiterOnly.length} signature(s) touch Jupiter/Raydium without drain markers`,
      polarity: "benign",
      weight: 6,
    })
    benign += 6
  }

  if (evidence.length === 0) {
    evidence.push({
      id: "no-signals",
      label: "Insufficient signals",
      detail: "Not enough on-chain patterns in the analysis window",
      polarity: "neutral",
      weight: 0,
    })
  }

  // Caveat note always useful on Solana
  evidence.push({
    id: "solana-caveat",
    label: "Solana classification caveat",
    detail:
      "Many Solana drainers make the victim sign System/Token transfers directly. Custom program IDs and batching are the strongest separators from SRP.",
    polarity: "neutral",
    weight: 0,
  })

  const { verdict, confidence } = scoreToVerdict(drainer, srp, benign)

  const timeline: TimelineTx[] = [...successful]
    .sort((a, b) => (a.blockTime ?? 0) - (b.blockTime ?? 0))
    .map((t) => {
      const methodParts: string[] = []
      if (t.unknownPrograms.length) methodParts.push("custom_program")
      if (t.solTransferCount) methodParts.push(`sol_xfer×${t.solTransferCount}`)
      if (t.tokenTransferCount)
        methodParts.push(`token_xfer×${t.tokenTransferCount}`)
      if (t.setAuthorityCount) methodParts.push("setAuthority")
      if (t.closeAccountCount) methodParts.push("closeAccount")
      if (methodParts.length === 0) methodParts.push("other")

      return {
        hash: t.signature,
        timestamp: t.blockTime ?? undefined,
        method: methodParts.join(", "),
        from: t.feePayer ?? victim,
        to: t.unknownPrograms[0] ?? SYSTEM_PROGRAM,
        direction: "out" as const,
        tokenOut:
          t.tokenTransferCount > 0
            ? `${t.tokenTransferCount} token transfer(s)`
            : undefined,
        notes: t.hasLookupTables ? "uses ALT" : undefined,
        explorerUrl: solanaTxUrl(t.signature),
      }
    })

  const summary = summarize(verdict, drainer, srp, benign)
  return { verdict, confidence, evidence, timeline, summary }
}

function summarize(
  verdict: Verdict,
  drainer: number,
  srp: number,
  benign: number
): string {
  switch (verdict) {
    case "DRAINER":
      return `Solana patterns match a drainer (custom programs, batch transfers, or authority changes). Drainer ${drainer} vs SRP ${srp}.`
    case "SRP_COMPROMISE":
      return `Solana patterns match key compromise sweeps (System/Token transfers only, possible account closes). SRP ${srp} vs drainer ${drainer}.`
    case "MIXED":
      return `Both drainer-style and SRP-style Solana signals present (drainer ${drainer}, SRP ${srp}).`
    case "LIKELY_BENIGN":
      return `No theft cluster detected on Solana in this window (benign ${benign}).`
    default:
      return `Inconclusive on Solana (drainer ${drainer}, SRP ${srp}, benign ${benign}).`
  }
}
