export type Verdict =
  | "DRAINER"
  | "SRP_COMPROMISE"
  | "MIXED"
  | "LIKELY_BENIGN"
  | "INCONCLUSIVE"

export type ChainFamily = "evm" | "solana"

export type EvidencePolarity = "drainer" | "srp" | "benign" | "neutral"

export interface EvidenceItem {
  id: string
  label: string
  detail: string
  polarity: EvidencePolarity
  weight: number
}

export interface TimelineTx {
  hash: string
  timestamp?: number
  method: string
  from: string
  to: string
  valueNative?: string
  tokenOut?: string
  direction: "in" | "out" | "self" | "unknown"
  notes?: string
  explorerUrl?: string
}

export interface AnalyzeRequest {
  query: string
  chain?: string
}

export interface AnalyzeResult {
  query: string
  queryType: "address" | "tx"
  family: ChainFamily
  chainId: string
  chainName: string
  victim?: string
  verdict: Verdict
  confidence: number
  evidence: EvidenceItem[]
  timeline: TimelineTx[]
  explorerUrls: { label: string; url: string }[]
  warnings: string[]
  summary: string
}

export interface LabelHit {
  address: string
  source: string
  tag?: string
}
