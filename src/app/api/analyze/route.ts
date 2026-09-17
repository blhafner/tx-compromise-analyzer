import { NextRequest, NextResponse } from "next/server"
import { analyzeQuery } from "@/lib/analyze"

export const dynamic = "force-dynamic"
export const maxDuration = 60

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as { query?: string; chain?: string }
    const query = body.query?.trim()
    if (!query) {
      return NextResponse.json({ error: "query is required" }, { status: 400 })
    }

    const result = await analyzeQuery(query, body.chain)
    return NextResponse.json(result)
  } catch (err) {
    const message = err instanceof Error ? err.message : "Analysis failed"
    return NextResponse.json({ error: message }, { status: 400 })
  }
}
