import type { EvidenceItem, TimelineTx, Verdict } from "../types"
import type { EvmChainConfig } from "../chains"
import { txExplorerUrl } from "../chains"
import {
  DRAINER_SELECTORS,
  TRANSFER_TOPIC,
  APPROVAL_TOPIC,
  APPROVAL_FOR_ALL_TOPIC,
  topicToAddress,
  isEmptyInput,
  decodeSelector,
} from "./decode"
import type { EnrichedTx, ExplorerTx, TokenTransfer } from "./fetch"
import type { LabelHit } from "../types"
import type { Transaction, TransactionReceipt } from "viem"

export interface EvmScoreInput {
  config: EvmChainConfig
  victim: string
  txs: EnrichedTx[]
  explorerTxs: ExplorerTx[]
  tokens: TokenTransfer[]
  labels: LabelHit[]
  focusTx?: Transaction
  focusReceipt?: TransactionReceipt
  nativeBalance: bigint
}

export interface EvmScoreResult {
  verdict: Verdict
  confidence: number
  evidence: EvidenceItem[]
  timeline: TimelineTx[]
  summary: string
}

function pushEvidence(
  list: EvidenceItem[],
  item: EvidenceItem
): void {
  list.push(item)
}

function scoreToVerdict(
  drainer: number,
  srp: number,
  benign: number
): { verdict: Verdict; confidence: number } {
  const total = drainer + srp + benign
  if (total === 0) {
    return { verdict: "INCONCLUSIVE", confidence: 15 }
  }

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
    return { verdict: "SRP_COMPROMISE", confidence: Math.max(35, confidence - 15) }
  }
  return { verdict: "INCONCLUSIVE", confidence: 25 }
}

export function scoreEvm(input: EvmScoreInput): EvmScoreResult {
  const { config, victim, explorerTxs, tokens, labels, focusTx, focusReceipt, nativeBalance } =
    input
  const evidence: EvidenceItem[] = []
  let drainer = 0
  let srp = 0
  let benign = 0

  const victimLower = victim.toLowerCase()
  const outbound = explorerTxs.filter((t) => t.from === victimLower && !t.isError)
  const inbound = explorerTxs.filter((t) => t.to === victimLower && t.from !== victimLower)

  // Label hits
  for (const hit of labels) {
    pushEvidence(evidence, {
      id: `label-${hit.source}-${hit.address}`,
      label: "Known malicious address",
      detail: `${hit.address} flagged by ${hit.source}${hit.tag ? ` (${hit.tag})` : ""}`,
      polarity: "drainer",
      weight: 25,
    })
    drainer += 25
  }

  // Method analysis on outbound
  let approveCount = 0
  let nativeOutCount = 0
  let transferOutCount = 0
  let contractCallCount = 0
  const collectors = new Map<string, number>()

  for (const t of outbound) {
    const method = decodeSelector(t.methodId ? `0x${t.methodId.replace(/^0x/, "")}` : t.input)
    if (
      [
        "approve",
        "increaseAllowance",
        "setApprovalForAll",
        "permit",
        "permit2.permit",
        "permit2.approve",
      ].includes(method)
    ) {
      approveCount++
    }
    if (isEmptyInput(t.input) && t.to) {
      nativeOutCount++
      collectors.set(t.to, (collectors.get(t.to) ?? 0) + 1)
    }
    if (method === "transfer") {
      transferOutCount++
      if (t.input && t.input.length >= 74) {
        const to = `0x${t.input.slice(34, 74)}`.toLowerCase()
        collectors.set(to, (collectors.get(to) ?? 0) + 1)
      }
    }
    if (!isEmptyInput(t.input)) {
      contractCallCount++
    }
  }

  // Token transfers where victim is from
  const victimTokenOut = tokens.filter((t) => t.from === victimLower)
  const externalPulls = tokens.filter(
    (t) =>
      t.from === victimLower &&
      // token tx hash may be initiated by someone else — check explorer txs
      !outbound.some((o) => o.hash === t.hash)
  )

  if (approveCount > 0) {
    pushEvidence(evidence, {
      id: "approvals",
      label: "Approval / permit signatures",
      detail: `${approveCount} approve/permit-style call(s) from the victim`,
      polarity: "drainer",
      weight: 12 + Math.min(approveCount * 3, 15),
    })
    drainer += 12 + Math.min(approveCount * 3, 15)
  }

  if (externalPulls.length > 0) {
    pushEvidence(evidence, {
      id: "external-pulls",
      label: "Assets pulled by third party",
      detail: `${externalPulls.length} token transfer(s) from victim without a matching victim-initiated tx (typical transferFrom drain)`,
      polarity: "drainer",
      weight: 20,
    })
    drainer += 20
  }

  // Focus tx receipt log analysis
  if (focusReceipt && focusTx) {
    const focusFrom = (focusTx.from ?? "").toLowerCase()
    const focusTo = (focusTx.to ?? "").toLowerCase()
    const method = decodeSelector(focusTx.input)

    if (focusFrom === victimLower && !isEmptyInput(focusTx.input as string)) {
      if (DRAINER_SELECTORS.has(method) || method.startsWith("unknown(")) {
        pushEvidence(evidence, {
          id: "focus-contract-call",
          label: "Focus tx is a contract interaction",
          detail: `Victim called ${method} on ${focusTo || "contract"}`,
          polarity: method === "transfer" ? "srp" : "drainer",
          weight: method === "transfer" ? 8 : 14,
        })
        if (method === "transfer") srp += 8
        else drainer += 14
      }
    }

    // EIP-7702 type 4
    const txType = (focusTx as { type?: string | number }).type
    if (txType === 4 || txType === "eip7702") {
      pushEvidence(evidence, {
        id: "eip7702",
        label: "EIP-7702 delegation",
        detail: "Transaction uses type-4 delegation — often abused by drainers",
        polarity: "drainer",
        weight: 18,
      })
      drainer += 18
    }

    let approvalLogs = 0
    let transferFromVictimInSameTx = 0
    for (const log of focusReceipt.logs) {
      const topic0 = log.topics[0]
      if (topic0 === APPROVAL_TOPIC || topic0 === APPROVAL_FOR_ALL_TOPIC) {
        const owner = topicToAddress(log.topics[1])
        if (owner === victimLower) approvalLogs++
      }
      if (topic0 === TRANSFER_TOPIC) {
        const from = topicToAddress(log.topics[1])
        if (from === victimLower && focusFrom !== victimLower) {
          transferFromVictimInSameTx++
        } else if (from === victimLower && focusFrom === victimLower && !isEmptyInput(focusTx.input as string) && method !== "transfer") {
          transferFromVictimInSameTx++
        }
      }
    }

    if (approvalLogs > 0) {
      pushEvidence(evidence, {
        id: "focus-approval-logs",
        label: "Approval events in focus tx",
        detail: `${approvalLogs} Approval/ApprovalForAll event(s) for victim`,
        polarity: "drainer",
        weight: 10,
      })
      drainer += 10
    }

    if (transferFromVictimInSameTx > 0 && method !== "transfer") {
      pushEvidence(evidence, {
        id: "same-tx-asset-move",
        label: "Assets moved in same phishing tx",
        detail: `${transferFromVictimInSameTx} Transfer event(s) from victim during a non-transfer call`,
        polarity: "drainer",
        weight: 16,
      })
      drainer += 16
    }
  }

  // Gas drip + sweep pattern (SRP)
  const smallInbound = inbound.filter((t) => {
    try {
      const v = BigInt(t.value || "0")
      return v > BigInt(0) && v < BigInt("100000000000000000") // < 0.1 native
    } catch {
      return false
    }
  })

  const sweepOutbound = outbound.filter((t) => {
    const isNative = isEmptyInput(t.input)
    const isTransfer = decodeSelector(t.input) === "transfer"
    return isNative || isTransfer
  })

  if (smallInbound.length > 0 && sweepOutbound.length >= 2) {
    // Check temporal clustering: drip before sweeps
    const dripTimes = smallInbound.map((t) => t.timeStamp)
    const sweepTimes = sweepOutbound.map((t) => t.timeStamp)
    const earliestSweep = Math.min(...sweepTimes)
    const dripBeforeSweep = dripTimes.some((d) => d <= earliestSweep + 3600)

    if (dripBeforeSweep) {
      pushEvidence(evidence, {
        id: "gas-drip",
        label: "Gas drip then sweep",
        detail: `${smallInbound.length} small inbound native transfer(s) followed by ${sweepOutbound.length} outbound sweep(s)`,
        polarity: "srp",
        weight: 22,
      })
      srp += 22
    }
  }

  if (nativeOutCount >= 2 && contractCallCount === 0) {
    pushEvidence(evidence, {
      id: "native-only-sweeps",
      label: "Simple native transfers only",
      detail: `${nativeOutCount} native send(s) with no contract calls — typical of key compromise sweeps`,
      polarity: "srp",
      weight: 14,
    })
    srp += 14
  }

  if (transferOutCount >= 1 && approveCount === 0 && externalPulls.length === 0) {
    pushEvidence(evidence, {
      id: "token-transfers",
      label: "Direct ERC-20 transfer() calls",
      detail: `${transferOutCount} transfer() from victim (not transferFrom)`,
      polarity: "srp",
      weight: 12,
    })
    srp += 12
  }

  const topCollectors = Array.from(collectors.entries()).sort(
    (a, b) => b[1] - a[1]
  )
  if (topCollectors.length > 0 && topCollectors.length <= 2 && (nativeOutCount + transferOutCount) >= 2) {
    pushEvidence(evidence, {
      id: "few-collectors",
      label: "Funds to few collector EOAs",
      detail: `Assets concentrated to ${topCollectors.length} address(es): ${topCollectors
        .map(([a, n]) => `${a.slice(0, 10)}…(${n})`)
        .join(", ")}`,
      polarity: "srp",
      weight: 10,
    })
    srp += 10
  }

  if (nativeBalance === BigInt(0) && (nativeOutCount > 0 || transferOutCount > 0 || victimTokenOut.length > 0)) {
    pushEvidence(evidence, {
      id: "empty-balance",
      label: "Victim native balance emptied",
      detail: "Current native balance is zero after outbound activity",
      polarity: "neutral",
      weight: 4,
    })
  }

  // Benign signals: single swap-like, no cluster
  if (
    outbound.length <= 2 &&
    approveCount === 0 &&
    externalPulls.length === 0 &&
    smallInbound.length === 0 &&
    victimTokenOut.length <= 1
  ) {
    pushEvidence(evidence, {
      id: "low-activity",
      label: "Low / ordinary activity",
      detail: "No approval cluster, gas drip, or multi-asset sweep detected in the window",
      polarity: "benign",
      weight: 8,
    })
    benign += 8
  }

  // Known DEX routers as to-address without asset loss cluster → benign lean
  const knownRouters = new Set([
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad", // universal router
    "0x1111111254eeb25477b68fb85ed929f73a960582", // 1inch
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff", // 0x
  ])
  const routerHits = outbound.filter((t) => knownRouters.has(t.to))
  if (routerHits.length > 0 && approveCount === 0 && externalPulls.length === 0) {
    pushEvidence(evidence, {
      id: "known-router",
      label: "Interaction with known DEX router",
      detail: `${routerHits.length} tx(s) to known swap routers without subsequent drain pulls`,
      polarity: "benign",
      weight: 6,
    })
    benign += 6
  }

  if (evidence.length === 0) {
    pushEvidence(evidence, {
      id: "no-signals",
      label: "Insufficient signals",
      detail: "Not enough on-chain patterns in the analysis window",
      polarity: "neutral",
      weight: 0,
    })
  }

  const { verdict, confidence } = scoreToVerdict(drainer, srp, benign)

  const timeline: TimelineTx[] = [...explorerTxs]
    .sort((a, b) => a.timeStamp - b.timeStamp)
    .slice(-40)
    .map((t) => {
      const method = decodeSelector(
        t.methodId ? `0x${t.methodId.replace(/^0x/, "")}` : t.input
      )
      const direction =
        t.from === victimLower && t.to === victimLower
          ? "self"
          : t.from === victimLower
            ? "out"
            : t.to === victimLower
              ? "in"
              : "unknown"
      const tokenNote = tokens
        .filter((tok) => tok.hash === t.hash)
        .map((tok) => `${tok.tokenSymbol ?? "TOKEN"}→${tok.to.slice(0, 8)}…`)
        .join(", ")

      return {
        hash: t.hash,
        timestamp: t.timeStamp,
        method,
        from: t.from,
        to: t.to,
        valueNative: t.value,
        tokenOut: tokenNote || undefined,
        direction,
        explorerUrl: txExplorerUrl(config, t.hash),
      }
    })

  // Also add token-only pulls not in explorer list
  for (const tok of externalPulls.slice(0, 10)) {
    if (timeline.some((t) => t.hash === tok.hash)) continue
    timeline.push({
      hash: tok.hash,
      timestamp: tok.timeStamp,
      method: "token_pull",
      from: tok.from,
      to: tok.to,
      tokenOut: `${tok.tokenSymbol ?? "TOKEN"} ${tok.value}`,
      direction: "out",
      notes: "Token transfer without victim-initiated matching tx",
      explorerUrl: txExplorerUrl(config, tok.hash),
    })
  }

  timeline.sort((a, b) => (a.timestamp ?? 0) - (b.timestamp ?? 0))

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
      return `Patterns strongly match a phishing/drainer flow (approvals, malicious contracts, or third-party pulls). Drainer score ${drainer} vs SRP ${srp}.`
    case "SRP_COMPROMISE":
      return `Patterns strongly match seed/key compromise sweeps (gas drip, native/token transfer() from the victim). SRP score ${srp} vs drainer ${drainer}.`
    case "MIXED":
      return `Both drainer-style and key-compromise-style signals appear in the window (drainer ${drainer}, SRP ${srp}). Manual review recommended.`
    case "LIKELY_BENIGN":
      return `No theft cluster detected; activity looks like ordinary sends/swaps (benign ${benign}).`
    default:
      return `Not enough distinct on-chain evidence to classify confidently (drainer ${drainer}, SRP ${srp}, benign ${benign}).`
  }
}
