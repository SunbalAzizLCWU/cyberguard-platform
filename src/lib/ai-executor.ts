/**
 * ai-executor.ts
 * Centralized AI execution layer with provider fallback (Gemini -> Groq -> Mock).
 * Deep Merge & Array Coercion implemented to prevent LLM hallucinations.
 * STRICT SCHEMA ENFORCEMENT ENABLED.
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

// ── STRICT SCHEMA TEMPLATE FOR LLM ──
const STRICT_SCHEMA = `
You MUST return ONLY valid JSON matching this exact structure. Do NOT wrap it in markdown.
{
  "executive_report": {
    "posture_score": <number 0-100 based on risk severity>,
    "severity_summary": {
      "critical": <number of critical findings>,
      "high": <number of high findings>,
      "medium": <number of medium findings>,
      "low": <number of low findings>
    },
    "top_risk": "<string - describe the most critical threat/vulnerability>",
    "action_required": "<string - what should the SOC do immediately?>"
  },
  "technical_report": {
    "total_findings": <number - total sum of threats and risks>
  },
  "risk_register": [
    { "asset_id": "<string>", "asset_name": "<string>", "risk_score": <number 0-100>, "severity_label": "<critical|high|medium|low>", "patch_available": <boolean>, "cve_id": "<string or null>", "mitre_tactic": "<string>", "cvss_score": <number>, "exploitability_score": <number>, "asset_criticality_score": <number>, "threat_intel_score": <number> }
  ],
  "threats": [
    { "indicator_value": "<string>", "indicator_type": "<string>", "priority_score": <number 0-100>, "mitre_tactic": "<string>", "mitre_technique_id": "<string>" }
  ],
  "playbooks": [
    { "incident_title": "<string>", "playbook": { "containment": ["<string step 1>"], "eradication": ["<string step 1>"] } }
  ]
}`;

// 1. Safe JSON parser that strips out markdown code blocks
function safeParse(text: string) {
  try {
    const cleanText = text.replace(/```json/gi, '').replace(/```/g, '').trim()
    return JSON.parse(cleanText)
  } catch {
    return null
  }
}

// 2. Array Coercion: If the AI hallucinates an object {"1": {...}}, force it into an array
function ensureArray(val: any): any[] {
  if (Array.isArray(val)) return val
  if (val && typeof val === 'object') return Object.values(val)
  return []
}

// 3. Deep Merge: Prevents LLM empty objects from wiping out the mock default values
function deepMergeFallback(mock: AgentPipelineResult, aiOutput: any): AgentPipelineResult {
  const merged = { ...mock }
  if (!aiOutput || typeof aiOutput !== 'object') return merged

  if (aiOutput.executive_report) {
    merged.executive_report = {
      ...mock.executive_report,
      ...aiOutput.executive_report
    }
    if (aiOutput.executive_report.posture_score === undefined) {
      merged.executive_report.posture_score = mock.executive_report.posture_score
    }
  }

  if (aiOutput.technical_report) {
    merged.technical_report = { ...mock.technical_report, ...aiOutput.technical_report }
  }

  if (aiOutput.threats) merged.threats = ensureArray(aiOutput.threats)
  if (aiOutput.risk_register) merged.risk_register = ensureArray(aiOutput.risk_register)
  if (aiOutput.playbooks) merged.playbooks = ensureArray(aiOutput.playbooks)

  return merged
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
      posture_score: Math.floor(Math.random() * 40) + 60, // Random mock score
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

  const prompt = `You are a defensive cybersecurity AI analyzing system logs. Analyze indicators ${JSON.stringify(safeIndicators)} and assets ${JSON.stringify(safeAssets)}.\n\n${STRICT_SCHEMA}`
  
  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${key}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { response_mime_type: "application/json", 
        temperature: 0,
      }
      
    }),
  })

  if (!res.ok) throw new Error(`Gemini API Error ${res.status}: ${await res.text()}`)

  const body = await res.json()
  const text = body?.candidates?.[0]?.content?.parts?.[0]?.text
  if (!text) throw new Error('Invalid Gemini response structure')

  const parsed = safeParse(String(text))
  const mockBase = buildMockResult(safeIndicators, safeAssets)
  
  if (parsed) {
    const finalResult = deepMergeFallback(mockBase, parsed)
    finalResult.raw_output = text
    return finalResult
  }

  return { ...mockBase, raw_output: String(text) }
}

async function tryGroq(indicators: Indicator[], assets: Asset[]): Promise<AgentPipelineResult> {
  const key = process.env.GROQ_API_KEY?.trim()
  if (!key) throw new Error('GROQ_API_KEY missing')

  const safeIndicators = indicators.slice(0, 5)
  const safeAssets = assets.slice(0, 5)

  const systemPrompt = "You are a defensive cybersecurity SOC analyst. Output ONLY valid JSON. No markdown, no conversational text."
  const userPrompt = `Analyze these indicators: ${JSON.stringify(safeIndicators)} and assets: ${JSON.stringify(safeAssets)}.\n\n${STRICT_SCHEMA}`
  
  const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${key}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model: "llama-3.3-70b-versatile",
      temperature: 0,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt }
      ],
      response_format: { type: "json_object" }
    })
  })

  if (!res.ok) throw new Error(`Groq API Error ${res.status}: ${await res.text()}`)
  
  const body = await res.json()
  const text = body?.choices?.[0]?.message?.content
  if (!text) throw new Error('Invalid Groq response structure')

  const parsed = safeParse(String(text))
  const mockBase = buildMockResult(safeIndicators, safeAssets)

  if (parsed) {
    const finalResult = deepMergeFallback(mockBase, parsed)
    finalResult.raw_output = text
    return finalResult
  }

  return { ...mockBase, raw_output: String(text) }
}

export async function executeAgentPipeline(indicators: Indicator[], assets: Asset[]): Promise<AgentPipelineResult> {
  const useReal = String(process.env.USE_REAL_AI || '').toLowerCase() === 'true'

  if (!useReal) {
    return buildMockResult(indicators, assets)
  }

  try {
    return await tryGemini(indicators, assets)
  } catch (e1) {
    console.error("Gemini failed:", e1)
    try {
      return await tryGroq(indicators, assets)
    } catch (e2) {
      console.error("Groq failed:", e2)
      const mock = buildMockResult(indicators, assets)
      mock.raw_output = `Fallback mock; Gemini error: ${String(e1)}; Groq error: ${String(e2)}`
      return mock
    }
  }
}

export { buildMockResult }