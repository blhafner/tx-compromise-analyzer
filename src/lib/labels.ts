import { readFileSync } from "fs"
import path from "path"
import type { LabelHit } from "./types"

const SCAMSNIFFER_URL =
  "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json"

let cachedScamSniffer: Set<string> | null = null
let scamSnifferFetchedAt = 0
const CACHE_TTL_MS = 6 * 60 * 60 * 1000

function loadLocalJsonSet(filename: string): Set<string> {
  try {
    const filePath = path.join(process.cwd(), "data", filename)
    const raw = readFileSync(filePath, "utf8")
    const parsed = JSON.parse(raw) as string[] | { addresses?: string[]; programs?: string[] }
    if (Array.isArray(parsed)) {
      return new Set(parsed.map((a) => a.toLowerCase()))
    }
    const list = parsed.addresses ?? parsed.programs ?? []
    return new Set(list.map((a) => a.toLowerCase()))
  } catch {
    return new Set()
  }
}

let localContracts: Set<string> | null = null
let localPrograms: Set<string> | null = null

function getLocalContracts(): Set<string> {
  if (!localContracts) localContracts = loadLocalJsonSet("drainer-contracts.json")
  return localContracts
}

function getLocalPrograms(): Set<string> {
  if (!localPrograms) {
    // Solana addresses are case-sensitive base58 — store as-is but also lower for safety
    try {
      const filePath = path.join(process.cwd(), "data", "drainer-programs.json")
      const raw = readFileSync(filePath, "utf8")
      const parsed = JSON.parse(raw) as string[] | { programs?: string[] }
      const list = Array.isArray(parsed) ? parsed : parsed.programs ?? []
      localPrograms = new Set(list)
    } catch {
      localPrograms = new Set()
    }
  }
  return localPrograms
}

async function getScamSnifferSet(): Promise<Set<string>> {
  const now = Date.now()
  if (cachedScamSniffer && now - scamSnifferFetchedAt < CACHE_TTL_MS) {
    return cachedScamSniffer
  }

  try {
    const res = await fetch(SCAMSNIFFER_URL, {
      next: { revalidate: 21600 },
    })
    if (!res.ok) throw new Error(`ScamSniffer HTTP ${res.status}`)
    const data = (await res.json()) as string[]
    cachedScamSniffer = new Set(data.map((a) => a.toLowerCase()))
    scamSnifferFetchedAt = now
    return cachedScamSniffer
  } catch {
    return cachedScamSniffer ?? new Set()
  }
}

export async function checkEvmLabels(
  addresses: string[]
): Promise<LabelHit[]> {
  const hits: LabelHit[] = []
  const scam = await getScamSnifferSet()
  const local = getLocalContracts()
  const seen = new Set<string>()

  for (const addr of addresses) {
    const lower = addr.toLowerCase()
    if (seen.has(lower)) continue
    seen.add(lower)

    if (local.has(lower)) {
      hits.push({ address: lower, source: "local-drainer-contracts", tag: "drainer" })
    }
    if (scam.has(lower)) {
      hits.push({ address: lower, source: "scamsniffer", tag: "phishing" })
    }
  }

  return hits
}

export function checkSolanaProgramLabels(programIds: string[]): LabelHit[] {
  const local = getLocalPrograms()
  const hits: LabelHit[] = []
  for (const id of programIds) {
    if (local.has(id)) {
      hits.push({ address: id, source: "local-drainer-programs", tag: "drainer" })
    }
  }
  return hits
}

export async function labelsAvailable(): Promise<{
  scamSniffer: boolean
  localContracts: number
  localPrograms: number
}> {
  const scam = await getScamSnifferSet()
  return {
    scamSniffer: scam.size > 0,
    localContracts: getLocalContracts().size,
    localPrograms: getLocalPrograms().size,
  }
}
