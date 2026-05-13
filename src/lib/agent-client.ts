/**
 * agent-client.ts
 * Typed client for the CyberGuard FastAPI agent server (port 8000).
 * Used by Next.js API routes to trigger and poll the CrewAI pipeline.
 */

const AGENT_BASE_URL = process.env.AGENT_API_URL ?? 'http://localhost:8001'

import { executeAgentPipeline, buildMockResult } from '@/lib/ai-executor'

// ── Types ──────────────────────────────────────────────────────────────────

export interface ThreatIndicator {
    type: 'ip' | 'domain' | 'hash' | 'cve' | 'url'
    value: string
    source: string
    confidence?: number
}

export interface Asset {
    id: string
    name: string
    type?: string
    ip_address?: string
    os?: string
    software?: { name: string; version: string }[]
    criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
    network_exposure?: 'internet-facing' | 'internal' | 'air-gapped'
    owner?: string
}

export interface AgentJobStatus {
    job_id: string
    status: 'queued' | 'running' | 'completed' | 'failed'
    created_at: string
    completed_at?: string | null
    result?: AgentPipelineResult | null
    error?: string | null
}

export interface AgentPipelineResult {
    metadata: {
        run_id: string
        processed_at: string
        indicators_processed: number
        assets_scanned: number
    }
    // Threat Intelligence Agent output
    threats?: ThreatIntelResult[]
    // Vulnerability Agent output
    vulnerabilities?: VulnerabilityResult[]
    // Risk Analyst output
    risk_register?: RiskResult[]
    // IR Agent output
    playbooks?: PlaybookResult[]
    // Reporter output
    executive_report?: ExecutiveReport
    technical_report?: TechnicalReport
    // Fallback if LLM wraps in raw_output
    raw_output?: string
}

export interface ThreatIntelResult {
    indicator_value: string
    indicator_type: string
    confidence_score: number
    mitre_tactic: string
    mitre_technique_id: string
    active_exploitation: boolean
    priority_score: number
}

export interface VulnerabilityResult {
    asset_id: string
    asset_name: string
    asset_criticality: string
    cve_id: string
    cvss_base_score: number
    patch_available: boolean
    match_confidence: number
    affected_component: string
}

export interface RiskResult {
    asset_id: string
    asset_name: string
    cve_id: string
    risk_score: number
    severity_label: string
    cvss_score: number
    exploitability_score: number
    asset_criticality_score: number
    threat_intel_score: number
    mitre_tactic: string
    patch_available: boolean
}

export interface PlaybookResult {
    cve_id: string
    asset_id: string
    risk_score: number
    playbook: {
        containment: string[]
        eradication: string[]
        recovery: string[]
    }
}

export interface ExecutiveReport {
    posture_score: number
    severity_summary: { critical: number; high: number; medium: number; low: number }
    top_risk: string
    action_required: string
}

export interface TechnicalReport {
    total_findings: number
    cves_detected: string[]
    assets_at_risk: string[]
    immediate_patches: string[]
}

// ── Client functions ───────────────────────────────────────────────────────

/**
 * Kick off the 5-agent pipeline. Returns job_id immediately (async job).
 */
export async function startAgentAnalysis(
    indicators: ThreatIndicator[],
    assets: Asset[],
    runId?: string
): Promise<AgentJobStatus> {
    // Minimal in-process job runner that preserves the external API contract.
    // If USE_REAL_AI !== 'true', executor will return a mock result immediately.
    const jobId = `cg-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    const created_at = new Date().toISOString()
    const initial: AgentJobStatus = {
        job_id: jobId,
        status: 'queued',
        created_at,
        completed_at: null,
        result: null,
        error: null,
    }

    const store = (global as any).__CG_AGENT_JOBS ||= new Map<string, AgentJobStatus>()
    store.set(jobId, initial)

    // Fire-and-forget pipeline processing
    ;(async () => {
        try {
            // mark running
            const running = { ...initial, status: 'running' as const }
            store.set(jobId, running)

            // Execute pipeline (Gemini -> Groq -> mock)
            const result = await executeAgentPipeline(indicators, assets)

            const completed_at = new Date().toISOString()
            const done: AgentJobStatus = {
                job_id: jobId,
                status: 'completed',
                created_at,
                completed_at,
                result,
                error: null,
            }
            store.set(jobId, done)
        } catch (e: any) {
            const failed_at = new Date().toISOString()
            const failed: AgentJobStatus = {
                job_id: jobId,
                status: 'failed',
                created_at,
                completed_at: failed_at,
                result: null,
                error: String(e?.message || e || 'Unknown error'),
            }
            store.set(jobId, failed)
        }
    })()

    return initial
}

/**
 * Check the status/result of a pipeline job.
 */
export async function getAgentJob(jobId: string): Promise<AgentJobStatus> {
    const store = (global as any).__CG_AGENT_JOBS ||= new Map<string, AgentJobStatus>()
    const job = store.get(jobId)
    if (!job) throw new Error(`Agent job not found: ${jobId}`)
    return job
}

/**
 * Poll a job until completed or failed.
 * @param jobId     The job to poll
 * @param intervalMs How often to poll (default: 4 seconds)
 * @param timeoutMs  Max wait time (default: 3 minutes)
 */
export async function waitForAgentJob(
    jobId: string,
    intervalMs = 4000,
    timeoutMs = 180_000
): Promise<AgentJobStatus> {
    const deadline = Date.now() + timeoutMs

    while (Date.now() < deadline) {
        const job = await getAgentJob(jobId)

        if (job.status === 'completed' || job.status === 'failed') {
            return job
        }

        await new Promise((r) => setTimeout(r, intervalMs))
    }

    throw new Error(`Agent job ${jobId} timed out after ${timeoutMs / 1000}s`)
}

/**
 * Quick synchronous risk score calculation (no agents needed).
 */
export async function calculateRiskScore(payload: {
    cvss_score: number
    exploit_availability: 'public' | 'poc' | 'theoretical'
    asset_criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
    active_exploitation: boolean
    network_exposure: 'internet-facing' | 'internal' | 'air-gapped'
}): Promise<{ risk_score: number; severity_label: string }> {
    const res = await fetch(`${AGENT_BASE_URL}/api/agents/score`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
    })

    if (!res.ok) throw new Error(`Risk score error: ${res.status}`)
    return res.json()
}

/**
 * Check if the FastAPI agent server is reachable.
 */
export async function checkAgentHealth(): Promise<boolean> {
    try {
        const res = await fetch(`${AGENT_BASE_URL}/health`, {
            signal: AbortSignal.timeout(3000),
        })
        return res.ok
    } catch {
        return false
    }
}
