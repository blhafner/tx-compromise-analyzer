"use client"

import { useState } from "react"
import { CHAIN_OPTIONS } from "@/lib/chain-options"
import type { AnalyzeResult, EvidenceItem, Verdict } from "@/lib/types"

const VERDICT_STYLES: Record<
  Verdict,
  { bg: string; border: string; label: string }
> = {
  DRAINER: {
    bg: "bg-[var(--drainer)]/15",
    border: "border-[var(--drainer)]",
    label: "Drainer / phishing",
  },
  SRP_COMPROMISE: {
    bg: "bg-[var(--srp)]/15",
    border: "border-[var(--srp)]",
    label: "SRP / key compromise",
  },
  MIXED: {
    bg: "bg-[var(--mixed)]/15",
    border: "border-[var(--mixed)]",
    label: "Mixed signals",
  },
  LIKELY_BENIGN: {
    bg: "bg-[var(--benign)]/15",
    border: "border-[var(--benign)]",
    label: "Likely benign",
  },
  INCONCLUSIVE: {
    bg: "bg-[var(--inconclusive)]/10",
    border: "border-[var(--inconclusive)]",
    label: "Inconclusive",
  },
}

function polarityColor(polarity: EvidenceItem["polarity"]): string {
  switch (polarity) {
    case "drainer":
      return "text-[var(--drainer)]"
    case "srp":
      return "text-[var(--srp)]"
    case "benign":
      return "text-[var(--benign)]"
    default:
      return "text-[var(--muted)]"
  }
}

function shortAddr(value: string, size = 6): string {
  if (value.length <= size * 2 + 2) return value
  return `${value.slice(0, size)}…${value.slice(-size)}`
}

function formatTime(ts?: number): string {
  if (!ts) return "—"
  return new Date(ts * 1000).toLocaleString()
}

export default function Home() {
  const [query, setQuery] = useState("")
  const [chain, setChain] = useState("auto")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<AnalyzeResult | null>(null)

  async function onAnalyze(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query, chain }),
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error || "Analysis failed")
        return
      }
      setResult(data as AnalyzeResult)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed")
    } finally {
      setLoading(false)
    }
  }

  const style = result ? VERDICT_STYLES[result.verdict] : null

  return (
    <main className="mx-auto max-w-3xl px-4 py-10 sm:py-14">
      <header className="mb-8">
        <p className="mb-2 text-sm uppercase tracking-[0.2em] text-[var(--muted)]">
          Compromise triage
        </p>
        <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">
          Drain vs SRP Analyzer
        </h1>
        <p className="mt-3 max-w-2xl text-[var(--muted)]">
          Paste an address or transaction hash. Heuristics classify activity as
          a phishing drainer, seed/key (SRP) compromise, mixed, or inconclusive
          across major EVM chains, Robinhood Chain, Arc, and Solana.
        </p>
      </header>

      <form
        onSubmit={onAnalyze}
        className="rounded-xl border border-[var(--border)] bg-[var(--bg-elevated)] p-4 sm:p-5"
      >
        <label className="mb-2 block text-sm text-[var(--muted)]" htmlFor="query">
          Address or transaction
        </label>
        <input
          id="query"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="0x… or Solana address / signature"
          className="mono w-full rounded-lg border border-[var(--border)] bg-[var(--bg)] px-3 py-3 text-sm outline-none ring-[var(--accent)] focus:ring-1"
          autoComplete="off"
          spellCheck={false}
        />

        <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-end">
          <div className="flex-1">
            <label
              className="mb-2 block text-sm text-[var(--muted)]"
              htmlFor="chain"
            >
              Chain
            </label>
            <select
              id="chain"
              value={chain}
              onChange={(e) => setChain(e.target.value)}
              className="w-full rounded-lg border border-[var(--border)] bg-[var(--bg)] px-3 py-2.5 text-sm outline-none ring-[var(--accent)] focus:ring-1"
            >
              {CHAIN_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
          <button
            type="submit"
            disabled={loading || !query.trim()}
            className="rounded-lg bg-[var(--accent)] px-5 py-2.5 text-sm font-medium text-white disabled:opacity-50"
          >
            {loading ? "Analyzing…" : "Analyze"}
          </button>
        </div>
      </form>

      {error && (
        <div className="mt-4 rounded-lg border border-[var(--drainer)]/40 bg-[var(--drainer)]/10 px-4 py-3 text-sm">
          {error}
        </div>
      )}

      {result && style && (
        <section className="mt-8 space-y-5">
          <div
            className={`rounded-xl border ${style.border} ${style.bg} p-5`}
          >
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <div>
                <p className="text-xs uppercase tracking-wider text-[var(--muted)]">
                  Verdict
                </p>
                <h2 className="text-2xl font-semibold">{style.label}</h2>
              </div>
              <div className="text-right">
                <p className="text-xs uppercase tracking-wider text-[var(--muted)]">
                  Confidence
                </p>
                <p className="text-2xl font-semibold tabular-nums">
                  {result.confidence}
                  <span className="text-base font-normal text-[var(--muted)]">
                    /100
                  </span>
                </p>
              </div>
            </div>
            <p className="mt-3 text-sm text-[var(--muted)]">{result.summary}</p>
            <dl className="mt-4 grid gap-2 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-[var(--muted)]">Chain</dt>
                <dd>
                  {result.chainName}{" "}
                  <span className="mono text-[var(--muted)]">
                    ({result.chainId})
                  </span>
                </dd>
              </div>
              <div>
                <dt className="text-[var(--muted)]">Query type</dt>
                <dd className="capitalize">{result.queryType}</dd>
              </div>
              {result.victim && (
                <div className="sm:col-span-2">
                  <dt className="text-[var(--muted)]">Victim / fee payer</dt>
                  <dd className="mono break-all text-xs sm:text-sm">
                    {result.victim}
                  </dd>
                </div>
              )}
            </dl>
            {result.explorerUrls.length > 0 && (
              <div className="mt-4 flex flex-wrap gap-3">
                {result.explorerUrls.map((link) => (
                  <a
                    key={link.url}
                    href={link.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-sm text-[var(--accent)] underline-offset-2 hover:underline"
                  >
                    {link.label} ↗
                  </a>
                ))}
              </div>
            )}
          </div>

          {result.warnings.length > 0 && (
            <div className="rounded-lg border border-[var(--srp)]/30 bg-[var(--srp)]/10 px-4 py-3 text-sm">
              <p className="mb-1 font-medium">Warnings</p>
              <ul className="list-disc space-y-1 pl-5 text-[var(--muted)]">
                {result.warnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-elevated)] p-5">
            <h3 className="mb-3 text-lg font-medium">Evidence</h3>
            <ul className="space-y-3">
              {result.evidence.map((item) => (
                <li
                  key={item.id}
                  className="border-b border-[var(--border)] pb-3 last:border-0 last:pb-0"
                >
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <span className="font-medium">{item.label}</span>
                    <span
                      className={`text-xs uppercase tracking-wide ${polarityColor(item.polarity)}`}
                    >
                      {item.polarity}
                      {item.weight > 0 ? ` · +${item.weight}` : ""}
                    </span>
                  </div>
                  <p className="mt-1 text-sm text-[var(--muted)]">
                    {item.detail}
                  </p>
                </li>
              ))}
            </ul>
          </div>

          <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-elevated)] p-5">
            <h3 className="mb-3 text-lg font-medium">Timeline</h3>
            {result.timeline.length === 0 ? (
              <p className="text-sm text-[var(--muted)]">No transactions in window.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-left text-sm">
                  <thead className="text-[var(--muted)]">
                    <tr className="border-b border-[var(--border)]">
                      <th className="py-2 pr-3 font-medium">Time</th>
                      <th className="py-2 pr-3 font-medium">Dir</th>
                      <th className="py-2 pr-3 font-medium">Method</th>
                      <th className="py-2 pr-3 font-medium">To</th>
                      <th className="py-2 font-medium">Tx</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.timeline.map((tx) => (
                      <tr
                        key={tx.hash + tx.method}
                        className="border-b border-[var(--border)]/60"
                      >
                        <td className="py-2 pr-3 whitespace-nowrap text-[var(--muted)]">
                          {formatTime(tx.timestamp)}
                        </td>
                        <td className="py-2 pr-3 uppercase text-xs">
                          {tx.direction}
                        </td>
                        <td className="mono py-2 pr-3 text-xs">
                          {tx.method}
                          {tx.tokenOut ? (
                            <span className="mt-0.5 block text-[var(--muted)]">
                              {tx.tokenOut}
                            </span>
                          ) : null}
                        </td>
                        <td className="mono py-2 pr-3 text-xs">
                          {shortAddr(tx.to)}
                        </td>
                        <td className="py-2">
                          {tx.explorerUrl ? (
                            <a
                              href={tx.explorerUrl}
                              target="_blank"
                              rel="noreferrer"
                              className="mono text-xs text-[var(--accent)] hover:underline"
                            >
                              {shortAddr(tx.hash, 4)}
                            </a>
                          ) : (
                            <span className="mono text-xs">
                              {shortAddr(tx.hash, 4)}
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <p className="text-xs leading-relaxed text-[var(--muted)]">
            Disclaimer: on-chain data cannot prove how a key was stolen (seed
            phishing vs malware vs clipboard) or that a signature was tricked
            versus intentional. This tool scores patterns and confidence only —
            not forensic proof.
          </p>
        </section>
      )}
    </main>
  )
}
