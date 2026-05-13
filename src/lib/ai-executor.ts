/**
 * ai-executor.ts
 * Centralized AI execution layer with provider fallback (Gemini -> Groq -> Mock).
 * Controlled by USE_REAL_AI, GEMINI_API_KEY, GROQ_API_KEY env vars.
 * Designed to be minimal, safe, and to preserve expected result shape.
 */

export interface Indicator { type: string; value: string; source?: string; confidence?: number }
export interface Asset { id: string; name: string; [k: string]: any }

export interface AgentPipelineResult {
  metadata: { run_id: string; processed_at: string; indicators_processed: number; assets_scanned: number }
  threats?: any[]
  vulnerabilities?: any[]
  risk_register?: any[]
  playbooks?: any[]
  executive_report?: any
  technical_report?: any
  raw_output?: string
}

// Safe JSON parser with fallback
function safeParse(text: string) {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

// Simple deterministic mock result to preserve API contract
function buildMockResult(indicators: Indicator[], assets: Asset[]): AgentPipelineResult {
  const now = new Date().toISOString()
  return {
    metadata: {
      run_id: `mock-${Date.now()}`,
      processed_at: now,
      indicators_processed: indicators.length,
      assets_scanned: assets.length,
    },
    threats: indicators.map((i, idx) => ({
      indicator_value: i.value,
      indicator_type: i.type || 'unknown',
      confidence_score: i.confidence ?? 50,
      mitre_tactic: 'unknown',
      mitre_technique_id: `T${1000 + idx}`,
      active_exploitation: false,
      priority_score: 50,
    })),
    risk_register: assets.map((a, idx) => ({
      asset_id: a.id,
      asset_name: a.name,
      cve_id: null,
      risk_score: 30 + idx,
      severity_label: 'medium',
      cvss_score: null,
      exploitability_score: 0,
      asset_criticality_score: 50,
      threat_intel_score: 10,
    })),
    playbooks: [],
    executive_report: {
      posture_score: Math.min(100, 60 + indicators.length),
      severity_summary: { critical: 0, high: 0, medium: indicators.length, low: assets.length },
      top_risk: indicators[0]?.value ?? '',
      action_required: 'Validate findings and patch where applicable',
    },
    technical_report: { total_findings: indicators.length, cves_detected: [], assets_at_risk: assets.map(a => a.name), immediate_patches: [] },
    raw_output: 'mock',
  }
}

async function tryGemini(indicators: Indicator[], assets: Asset[]): Promise<AgentPipelineResult> {
  const key = process.env.GEMINI_API_KEY
  if (!key) throw new Error('GEMINI_API_KEY missing')

  // Prevent token explosion by limiting inputs
  const safeIndicators = indicators.slice(0, 5)
  const safeAssets = assets.slice(0, 5)

  // This is a best-effort wrapper — keep it safe and timeout quickly
  const prompt = `Analyze indicators ${JSON.stringify(safeIndicators)} and assets ${JSON.stringify(safeAssets)} and return a JSON object with executive_report, risk_register, threats, playbooks.`
  try {
    const res = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${key}', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${key}` },
      body: JSON.stringify({
      contents: [
        {
          parts: [
            {
              text: prompt
            }
          ]
        }
      ]
    }),
      // no signal here — rely on default network timeouts in Node/hosting
    })

    if (!res.ok) throw new Error(`Gemini error ${res.status}`)

    const body = await res.json()
    // Extract JSON from Gemini response with proper validation
    const text = body?.candidates?.[0]?.content?.parts?.[0]?.text
    if (!text) {
      throw new Error('Invalid Gemini response structure')
    }

    const parsed = safeParse(String(text))
    if (parsed) {
      return {
        ...buildMockResult(safeIndicators, safeAssets),
        ...parsed,
        raw_output: text
      }
    }

    // If provider returned plain text, wrap it
    return { ...buildMockResult(safeIndicators, safeAssets), raw_output: String(text) }
  } catch (e) {
    throw new Error(`Gemini provider failed: ${String(e)}`)
  }
}

async function tryGroq(indicators: Indicator[], assets: Asset[]): Promise<AgentPipelineResult> {
  const key = process.env.GROQ_API_KEY
  if (!key) throw new Error('GROQ_API_KEY missing')

  // Prevent token explosion by limiting inputs
  const safeIndicators = indicators.slice(0, 5)
  const safeAssets = assets.slice(0, 5)

  const prompt = `Analyze indicators ${JSON.stringify(safeIndicators)} and assets ${JSON.stringify(safeAssets)} and emit JSON with executive_report, risk_register, threats, playbooks.`
  try {
    const res = await fetch(
  "https://api.groq.com/openai/v1/chat/completions",
  {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${key}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model: "llama3-8b-8192",
      messages: [
        { role: "user", content: prompt }
      ]
    })
  }
)

    if (!res.ok) throw new Error(`Groq error ${res.status}`)
    const body = await res.json()
    const text = body?.choices?.[0]?.message?.content
    if (!text) {
      throw new Error('Invalid Groq response structure')
    }

    const parsed = safeParse(String(text))
    if (parsed) {
      return {
        ...buildMockResult(safeIndicators, safeAssets),
        ...parsed,
        raw_output: text
      }
    }

    return { ...buildMockResult(safeIndicators, safeAssets), raw_output: String(text) }
  } catch (e) {
    throw new Error(`Groq provider failed: ${String(e)}`)
  }
}

export async function executeAgentPipeline(indicators: Indicator[], assets: Asset[]): Promise<AgentPipelineResult> {
  const useReal = String(process.env.USE_REAL_AI || '').toLowerCase() === 'true'

  if (!useReal) {
    return buildMockResult(indicators, assets)
  }

  // Try Gemini first, then Groq, then mock
  try {
    return await tryGemini(indicators, assets)
  } catch (e1) {
    try {
      return await tryGroq(indicators, assets)
    } catch (e2) {
      // Last resort: return mock result but include errors in raw_output
      const mock = buildMockResult(indicators, assets)
      mock.raw_output = `Fallback mock; Gemini error: ${String(e1)}; Groq error: ${String(e2)}`
      return mock
    }
  }
}

export { buildMockResult }
