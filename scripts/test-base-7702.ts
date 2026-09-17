import { analyzeQuery } from "../src/lib/analyze"

async function main() {
  const r = await analyzeQuery(
    "0x57114E59A278EC52276e207Ee29460171206538B",
    "base"
  )
  console.log(
    JSON.stringify(
      {
        chain: r.chainName,
        verdict: r.verdict,
        confidence: r.confidence,
        timeline: r.timeline.length,
        warnings: r.warnings,
        evidence: r.evidence.map((e) => ({
          id: e.id,
          polarity: e.polarity,
          weight: e.weight,
          label: e.label,
          detail: e.detail,
        })),
        summary: r.summary,
      },
      null,
      2
    )
  )
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
