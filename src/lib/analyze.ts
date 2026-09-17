import { detectQuery } from "./detect"
import {
  addressExplorerUrl,
  getEvmChainByKey,
  solanaAddressUrl,
  solanaTxUrl,
  txExplorerUrl,
} from "./chains"
import { checkEvmLabels, checkSolanaProgramLabels } from "./labels"
import {
  enrichTxs,
  fetchAddressHistory,
  findTxAcrossChains,
  getNativeBalance,
  windowAroundNonce,
} from "./evm/fetch"
import { scoreEvm } from "./evm/score"
import {
  fetchSolanaAddressActivity,
  fetchSolanaTransaction,
  windowAroundSignature,
} from "./solana/fetch"
import { scoreSolana } from "./solana/score"
import type { AnalyzeResult } from "./types"

export async function analyzeQuery(
  query: string,
  chainHint?: string
): Promise<AnalyzeResult> {
  const detected = detectQuery(query, chainHint)

  if (detected.family === "solana") {
    return analyzeSolana(detected.raw, detected.kind === "solana_tx")
  }
  return analyzeEvm(
    detected.raw,
    detected.kind === "evm_tx",
    detected.preferredChainKey
  )
}

async function analyzeEvm(
  raw: string,
  isTx: boolean,
  preferredChainKey?: string
): Promise<AnalyzeResult> {
  const warnings: string[] = []

  if (isTx) {
    const found = await findTxAcrossChains(raw, preferredChainKey)
    if (!found) {
      throw new Error(
        "Transaction not found on supported EVM chains. Try selecting a chain explicitly."
      )
    }

    const { config, tx, receipt } = found
    const victim = (tx.from ?? "").toLowerCase()
    const { txs: history, tokens, warnings: histWarn } =
      await fetchAddressHistory(config, victim, 80)
    warnings.push(...histWarn)

    let window = history
    if (typeof tx.nonce === "number") {
      window = windowAroundNonce(history, Number(tx.nonce), 20)
      // Ensure focus tx is present
      if (!window.some((t) => t.hash === raw.toLowerCase())) {
        window = [
          {
            hash: raw.toLowerCase(),
            from: victim,
            to: (tx.to ?? "").toLowerCase(),
            value: (tx.value ?? BigInt(0)).toString(),
            input: (tx.input as string) ?? "0x",
            timeStamp: 0,
            nonce: Number(tx.nonce),
          },
          ...window,
        ]
      }
    }

    const enriched = await enrichTxs(config, window, raw)
    const counterparties = [
      victim,
      ...(tx.to ? [tx.to.toLowerCase()] : []),
      ...window.map((t) => t.to).filter(Boolean),
      ...window.map((t) => t.from).filter(Boolean),
    ]
    const labels = await checkEvmLabels(counterparties)
    const nativeBalance = await getNativeBalance(config, victim)

    const scored = scoreEvm({
      config,
      victim,
      txs: enriched,
      explorerTxs: window,
      tokens,
      labels,
      focusTx: tx,
      focusReceipt: receipt,
      nativeBalance,
    })

    return {
      query: raw,
      queryType: "tx",
      family: "evm",
      chainId: String(config.id),
      chainName: config.name,
      victim,
      verdict: scored.verdict,
      confidence: scored.confidence,
      evidence: scored.evidence,
      timeline: scored.timeline,
      explorerUrls: [
        { label: "Transaction", url: txExplorerUrl(config, raw) },
        { label: "Victim", url: addressExplorerUrl(config, victim) },
      ],
      warnings,
      summary: scored.summary,
    }
  }

  // Address mode — need a chain
  if (!preferredChainKey) {
    // Probe etherscan-supported chains for recent activity; pick first with txs
    const probeOrder = [
      "ethereum",
      "base",
      "arbitrum",
      "bsc",
      "polygon",
      "optimism",
      "robinhood",
      "arc",
    ]
    let best:
      | {
          key: string
          count: number
        }
      | undefined

    for (const key of probeOrder) {
      const config = getEvmChainByKey(key)
      if (!config) continue
      try {
        const { txs, warnings: w } = await fetchAddressHistory(config, raw, 10)
        warnings.push(...w)
        if (txs.length > (best?.count ?? 0)) {
          best = { key, count: txs.length }
        }
        // Prefer first chain with meaningful activity
        if (txs.length >= 3) {
          preferredChainKey = key
          break
        }
      } catch {
        // continue
      }
    }
    if (!preferredChainKey) {
      preferredChainKey = best?.key ?? "ethereum"
      warnings.push(
        `Auto-selected ${preferredChainKey} (most recent activity found, or default). Select a chain if this looks wrong.`
      )
    }
  }

  const config = getEvmChainByKey(preferredChainKey)
  if (!config) throw new Error(`Unknown chain ${preferredChainKey}`)

  const { txs: history, tokens, warnings: histWarn } =
    await fetchAddressHistory(config, raw, 50)
  warnings.push(...histWarn)

  // Filter roughly to last 7 days if timestamps exist
  const now = Math.floor(Date.now() / 1000)
  const weekAgo = now - 7 * 24 * 3600
  let window = history.filter((t) => !t.timeStamp || t.timeStamp >= weekAgo)
  if (window.length < 5) window = history

  const enriched = await enrichTxs(config, window)
  const counterparties = [
    raw.toLowerCase(),
    ...window.flatMap((t) => [t.from, t.to]).filter(Boolean),
  ]
  const labels = await checkEvmLabels(counterparties)
  const nativeBalance = await getNativeBalance(config, raw)

  const scored = scoreEvm({
    config,
    victim: raw.toLowerCase(),
    txs: enriched,
    explorerTxs: window,
    tokens,
    labels,
    nativeBalance,
  })

  return {
    query: raw,
    queryType: "address",
    family: "evm",
    chainId: String(config.id),
    chainName: config.name,
    victim: raw.toLowerCase(),
    verdict: scored.verdict,
    confidence: scored.confidence,
    evidence: scored.evidence,
    timeline: scored.timeline,
    explorerUrls: [
      { label: "Address", url: addressExplorerUrl(config, raw) },
    ],
    warnings,
    summary: scored.summary,
  }
}

async function analyzeSolana(
  raw: string,
  isTx: boolean
): Promise<AnalyzeResult> {
  const warnings: string[] = []

  if (isTx) {
    const focus = await fetchSolanaTransaction(raw)
    if (!focus) {
      throw new Error("Solana transaction not found")
    }
    warnings.push(...focus.warnings)

    const victim = focus.tx.feePayer
    let windowTxs = [focus.tx]

    if (victim) {
      const around = await windowAroundSignature(victim, raw, 20)
      warnings.push(...around.warnings)
      if (around.txs.length > 0) {
        windowTxs = around.txs
        if (!windowTxs.some((t) => t.signature === raw)) {
          windowTxs = [focus.tx, ...windowTxs]
        }
      }
    }

    const programIds = Array.from(
      new Set(windowTxs.flatMap((t) => t.programIds))
    )
    const labels = checkSolanaProgramLabels(programIds)
    const scored = scoreSolana({
      victim: victim ?? "unknown",
      txs: windowTxs,
      labels,
      focus: focus.tx,
    })

    return {
      query: raw,
      queryType: "tx",
      family: "solana",
      chainId: "solana",
      chainName: "Solana",
      victim,
      verdict: scored.verdict,
      confidence: scored.confidence,
      evidence: scored.evidence,
      timeline: scored.timeline,
      explorerUrls: [
        { label: "Transaction", url: solanaTxUrl(raw) },
        ...(victim
          ? [{ label: "Fee payer", url: solanaAddressUrl(victim) }]
          : []),
      ],
      warnings,
      summary: scored.summary,
    }
  }

  const activity = await fetchSolanaAddressActivity(raw, 40)
  warnings.push(...activity.warnings)

  const programIds = Array.from(
    new Set(activity.txs.flatMap((t) => t.programIds))
  )
  const labels = checkSolanaProgramLabels(programIds)
  const scored = scoreSolana({
    victim: raw,
    txs: activity.txs,
    labels,
  })

  return {
    query: raw,
    queryType: "address",
    family: "solana",
    chainId: "solana",
    chainName: "Solana",
    victim: raw,
    verdict: scored.verdict,
    confidence: scored.confidence,
    evidence: scored.evidence,
    timeline: scored.timeline,
    explorerUrls: [{ label: "Account", url: solanaAddressUrl(raw) }],
    warnings,
    summary: scored.summary,
  }
}