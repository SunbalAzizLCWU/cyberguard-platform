import { NextRequest, NextResponse } from 'next/server'
import { executeAgentPipeline } from '@/lib/ai-executor'
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
    { auth: { persistSession: false, autoRefreshToken: false } }
)

// Force Vercel to allow this function to run for up to 60 seconds
export const maxDuration = 60

export async function POST(req: NextRequest) {
    try {
        const body = await req.json()
        const { indicators, assets } = body

        // 1. Run the AI Pipeline synchronously (Server stays awake)
        const result = await executeAgentPipeline(indicators || [], assets || [])
        const jobId = `cg-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

        // 2. Save directly to Supabase immediately after AI finishes
        await saveResultsToSupabase(jobId, result)
        
        // 3. Emit socket event
        await pushToSocket(result)

        // 4. Return the completed job to the UI
        return NextResponse.json({ 
            success: true,
            job_id: jobId, 
            job: {
                status: 'completed',
                result: result
            }
        })
    } catch (error: any) {
        console.error('[API] Threat Pipeline Error:', error)
        return NextResponse.json({ success: false, error: error.message }, { status: 500 })
    }
}

async function saveResultsToSupabase(jobId: string, result: any) {
    const now = new Date().toISOString()
    const summary = { threats: 0, risks: 0, incidents: 0, playbooks: 0, reports: 0 }
    const logError = (label: string, error: unknown) => {
        console.error(`[Supabase] ${label}:`, error)
    }

    // CRASH FIX: Ensure threats is strictly an Array before iterating
    const threats: any[] = Array.isArray(result.threats) ? result.threats : []
    for (const t of threats) {
        try {
            const { error } = await supabase.from('Threat').insert({
                id:          `thr-agent-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
                title:       `[AI] ${t.indicator_value ?? 'Unknown Indicator'}`,
                description: `MITRE: ${t.mitre_tactic ?? 'Unknown'} (${t.mitre_technique_id ?? 'N/A'}) — detected by AI pipeline`,
                severity:    priorityToSeverity(t.priority_score ?? 50),
                status:      'active',
                source:      'AI Agent',
                cveId:       t.indicator_type === 'cve' ? t.indicator_value : null,
                ipAddress:   t.indicator_type === 'ip'  ? t.indicator_value : null,
                detected:    now,
                updatedAt:   now,
            })
            if (!error) summary.threats++
            else logError('Threat insert error', error.message)
        } catch (error) {
            logError('Threat insert exception', error)
        }
    }

    // CRASH FIX: Ensure riskRegister is strictly an Array before iterating
    const riskRegister: any[] = Array.isArray(result.risk_register) ? result.risk_register : []
    for (const r of riskRegister) {
        try {
            const { error } = await supabase.from('RiskAnalysis').insert({
                id:             `risk-agent-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
                assetId:        r.asset_id   ?? 'unknown',
                assetName:      r.asset_name ?? 'Unknown Asset',
                riskLevel:      Math.round(Math.min(100, r.risk_score ?? 0)),
                cvssScore:      r.cvss_score ?? null,
                exploitability: exploitabilityLabel(r.exploitability_score ?? 0),
                patchAvailable: r.patch_available ?? false,
                scoreBreakdown: `CVSS:${r.cvss_score} | Exploit:${r.exploitability_score} | Asset:${r.asset_criticality_score} | ThreatIntel:${r.threat_intel_score}`,
                mitreAttack:    r.mitre_tactic ?? null,
                created:        now,
                updatedAt:      now,
            })
            if (!error) summary.risks++
            else logError('RiskAnalysis insert error', error.message)
        } catch (error) {
            logError('RiskAnalysis insert exception', error)
        }
    }

    const highPlusFindings = riskRegister.filter(r => (r.risk_score ?? 0) >= 50)
    for (const r of highPlusFindings) {
        try {
            const { error } = await supabase.from('Incident').insert({
                id:          `inc-agent-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
                incidentId:  `INC-AI-${Date.now()}`,
                title:       `[AI] ${r.cve_id ?? 'Vulnerability'} on ${r.asset_name ?? 'Unknown Asset'}`,
                description: `Risk score ${r.risk_score}/100 (${r.severity_label}). MITRE: ${r.mitre_tactic ?? 'N/A'}. Auto-created by AI agent pipeline. Patch available: ${r.patch_available ? 'Yes' : 'No'}.`,
                severity:    r.severity_label?.toLowerCase() ?? 'high',
                status:      'open',
                assignee:    'Unassigned',
                created:     now,
                updatedAt:   now,
            })
            if (!error) summary.incidents++
            else logError('Incident insert error', error.message)
        } catch (error) {
            logError('Incident insert exception', error)
        }
    }

    // CRASH FIX: Ensure playbooks is strictly an Array before iterating
    const playbooks: any[] = Array.isArray(result.playbooks) ? result.playbooks : []
    for (const p of playbooks) {
        try {
            const { error } = await supabase.from('Playbook').insert({
                id:          `pb-agent-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
                title:       p.incident_title ?? `[AI] ${p.cve_id ?? 'Threat'} Response Playbook`,
                description: p.incident_summary ?? 'Auto-generated by CyberGuard AI Incident Response Agent',
                category:    'AI Generated',
                content:     p.playbook ?? {},
                cveId:       p.cve_id ?? null,
                updatedAt:   now,
                created:     now,
            })
            if (!error) summary.playbooks++
            else logError('Playbook insert error', error.message)
        } catch (error) {
            logError('Playbook insert exception', error)
        }
    }

    const execReport = result.executive_report ?? {}
    const techReport = result.technical_report ?? {}
    const compReport = result.compliance_report ?? {}

    if (execReport.top_risk || techReport.total_findings) {
        try {
            const { error } = await supabase.from('Report').insert({
                id:        `rep-agent-${jobId}`,
                title:     `AI Analysis Report — ${new Date().toLocaleDateString('en-US', { dateStyle: 'medium' })}`,
                type:      'executive',
                status:    'final',
                content:   {
                    executive_report:  execReport,
                    technical_report:  techReport,
                    compliance_report: compReport,
                },
                jobId:     jobId,
                generated: now,
            })
            if (!error) summary.reports++
            else logError('Report insert error', error.message)
        } catch (error) {
            logError('Report insert exception', error)
        }
    }

    return summary
}

async function pushToSocket(result: any) {
    const appUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'
    const execReport = result.executive_report ?? {}

    try {
        await fetch(`${appUrl}/api/internal/socket-emit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                event: 'agent:complete',
                data: {
                    result: {
                        threats:     Array.isArray(result.threats) ? result.threats : [],
                        risk_scores: Array.isArray(result.risk_register) ? result.risk_register : [],
                        metrics: {
                            postureScore:   execReport.posture_score                ?? 0,
                            criticalCount:  execReport.severity_summary?.critical   ?? 0,
                            highCount:      execReport.severity_summary?.high       ?? 0,
                            totalFindings:  result.technical_report?.total_findings ?? 0,
                            topRisk:        execReport.top_risk                     ?? '',
                            actionRequired: execReport.action_required              ?? '',
                        },
                    },
                },
            }),
        })
    } catch (e) {
        // Silently ignore socket errors
    }
}

function priorityToSeverity(score: number): string {
    if (score >= 80) return 'critical'
    if (score >= 60) return 'high'
    if (score >= 40) return 'medium'
    return 'low'
}

function exploitabilityLabel(score: number): string {
    if (score >= 9) return 'PUBLIC'
    if (score >= 5) return 'POC_ONLY'
    if (score >= 1) return 'THEORETICAL'
    return 'NONE'
}