/**
 * ai-executor.ts
 * Centralized AI execution layer with provider fallback (Gemini -> Groq -> Mock).
 * Controlled by USE_REAL_AI, GEMINI_API_KEY, GROQ_API_KEY env vars.
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

// Safe JSON parser that strips out markdown code blocks if the AI includes them
function safeParse(text: string) {
  try {
    const cleanText = text.replace(/```json/gi, '').replace(/```/g, '').trim()
    return JSON.parse(cleanText)
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
      posture_score: Math.floor(Math.random() * 40) + 60, // Random score for mock
      severity_summary: { critical: 0, high: 0, medium: indicators.length, low: assets.length },
      top_risk: indicators[Math.floor(Math.random() * indicators.length)]?.value ?? '',
      action_required: 'Validate findings and patch where applicable',
    },
    technical_report: { total_findings: indicators.length, cves_detected: [], assets_at_risk: assets.map(a => a.name), immediate_patches: [] },
    raw_output: 'mock',
  }
}

async function tryGemini(indicators: Indicator[], assets: Asset[]): Promise<AgentPipelineResult> {
  const key = process.env.GEMINI_API_KEY?.trim()
  if (!key) throw new Error('GEMINI_API_KEY missing')

  const safeIndicators = indicators.slice(0, 5)
  const safeAssets = assets.slice(0, 5)

  // FIXED: Explicitly asking for arrays
  const prompt = `You are a defensive cybersecurity AI analyzing system logs. Analyze indicators ${JSON.stringify(safeIndicators)} and assets ${JSON.stringify(safeAssets)}. Emit JSON containing exactly these keys: "executive_report" (object), "risk_register" (array of objects), "threats" (array of objects), "playbooks" (array of objects).`
  
  try {
    const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${key}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { response_mime_type: "application/json" } // Force JSON mode
      }),
    })

    if (!res.ok) {
      const errText = await res.text()
      throw new Error(`Gemini API Error ${res.status}: ${errText}`)
    }

    const body = await res.json()
    const text = body?.candidates?.[0]?.content?.parts?.[0]?.text
    if (!text) throw new Error('Invalid Gemini response structure')

    const parsed = safeParse(String(text))
    if (parsed) return { ...buildMockResult(safeIndicators, safeAssets), ...parsed, raw_output: text }

    return { ...buildMockResult(safeIndicators, safeAssets), raw_output: String(text) }
  } catch (e) {
    throw new Error(`Gemini provider failed: ${String(e)}`)
  }
}

async function tryGroq(indicators: Indicator[], assets: Asset[]): Promise<AgentPipelineResult> {
  const key = process.env.GROQ_API_KEY?.trim()
  if (!key) throw new Error('GROQ_API_KEY missing')

  const safeIndicators = indicators.slice(0, 5)
  const safeAssets = assets.slice(0, 5)

  const systemPrompt = "You are a defensive cybersecurity SOC analyst. Output ONLY valid JSON. No markdown, no conversational text."
  // FIXED: Explicitly asking for arrays
  const userPrompt = `Analyze these indicators: ${JSON.stringify(safeIndicators)} and assets: ${JSON.stringify(safeAssets)}. Emit JSON containing exactly these keys: "executive_report" (object), "risk_register" (array of objects), "threats" (array of objects), "playbooks" (array of objects).`
  
  try {
    const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${key}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "llama-3.3-70b-versatile",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt }
        ],
        response_format: { type: "json_object" } // Force JSON mode
      })
    })

    if (!res.ok) {
      const errText = await res.text()
      throw new Error(`Groq API Error ${res.status}: ${errText}`)
    }
    
    const body = await res.json()
    const text = body?.choices?.[0]?.message?.content
    if (!text) throw new Error('Invalid Groq response structure')

    const parsed = safeParse(String(text))
    if (parsed) return { ...buildMockResult(safeIndicators, safeAssets), ...parsed, raw_output: text }

    return { ...buildMockResult(safeIndicators, safeAssets), raw_output: String(text) }
  } catch (e) {
    throw new Error(`Groq provider failed: ${String(e)}`)
  }
}

export async function executeAgentPipeline(indicators: Indicator[], assets: Asset[]): Promise<AgentPipelineResult> {
  console.log("USE_REAL_AI:", process.env.USE_REAL_AI)
  const useReal = String(process.env.USE_REAL_AI || '').toLowerCase() === 'true'

  if (!useReal) {
    console.log("⚠️ Using MOCK (USE_REAL_AI is not true)")
    return buildMockResult(indicators, assets)
  }

  console.log("✅ REAL AI MODE ENABLED")

  // Try Gemini first
  try {
    console.log("🚀 Trying Gemini...")
    const result = await tryGemini(indicators, assets)
    console.log("✅ Gemini SUCCESS")
    return result
  } catch (e1) {
    console.log("❌ Gemini FAILED:", e1)

    // Try Groq
    try {
      console.log("🚀 Trying Groq...")
      const result = await tryGroq(indicators, assets)
      console.log("✅ Groq SUCCESS")
      return result
    } catch (e2) {
      console.log("❌ Groq FAILED:", e2)

      // Final fallback
      console.log("⚠️ Using FINAL MOCK fallback")
      const mock = buildMockResult(indicators, assets)
      mock.raw_output = `Fallback mock; Gemini error: ${String(e1)}; Groq error: ${String(e2)}`
      return mock
    }
  }
}

export { buildMockResult }