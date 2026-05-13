/**
 * GET /api/threats/job?jobId=cg-xxx
 * Polls the Python agent pipeline, then saves ALL results to Supabase
 * tables that other pages (Threats, Risk, Incidents, Playbooks, Reports) read from.
 */

import { NextRequest, NextResponse } from 'next/server'
import { getAgentJob } from '@/lib/agent-client'
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
    { auth: { persistSession: false, autoRefreshToken: false } }
)

// Track which jobs we've already saved to avoid duplicate DB writes on every poll
const savedJobs = new Set<string>()

export async function GET(request: NextRequest) {
    const jobId = request.nextUrl.searchParams.get('jobId')

    if (!jobId) {
        return NextResponse.json(
            { success: false, error: 'jobId query param required' },
            { status: 400 }
        )
    }

    try {
        const job = await getAgentJob(jobId)

        // Only save once — polling hits this endpoint every 4s
        if (job.status === 'completed' && job.result && !savedJobs.has(jobId)) {
            savedJobs.add(jobId)
            console.log(`[Job ${jobId}] Pipeline complete — saving to Supabase...`)

            const saveResult = await saveResultsToSupabase(jobId, job.result)
            console.log(`[Job ${jobId}] Save complete:`, saveResult)

            await pushToSocket(job.result)
        }

        return NextResponse.json({ success: true, job })

    } catch (error: any) {
        console.error('[API] Error polling job:', error)
        return NextResponse.json(
            { success: false, error: error.message },
            { status: 500 }
        )
    }
}


async function saveResultsToSupabase(jobId: string, result: any) {
    const now = new Date().toISOString()
    const summary = { threats: 0, risks: 0, incidents: 0, playbooks: 0, reports: 0 }

    // ── 1. Save Threats ───────────────────────────────────────────────────
    const threats: any[] = result.threats ?? []
    for (const t of threats) {
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
            updatedAt:     now,
        })
        if (!error) summary.threats++
        else console.error('[Supabase] Threat insert error:', error.message)
    }

    // ── 2. Save Risk Analysis ─────────────────────────────────────────────
    const riskRegister: any[] = result.risk_register ?? []
    for (const r of riskRegister) {
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
            updatedAt:      now, // <-- FIXED: Changed from 'updated' to 'updatedAt' to match your Supabase schema
        })
        if (!error) summary.risks++
        else console.error('[Supabase] RiskAnalysis insert error:', error.message)
    }

    // ── 3. Save Incidents for CRITICAL + HIGH findings (risk >= 50) ───────
    const highPlusFindings = riskRegister.filter(r => (r.risk_score ?? 0) >= 50)
    for (const r of highPlusFindings) {
        const { error } = await supabase.from('Incident').insert({
            id:          `inc-agent-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
            incidentId:  `INC-AI-${Date.now()}`,
            title:       `[AI] ${r.cve_id ?? 'Vulnerability'} on ${r.asset_name ?? 'Unknown Asset'}`,
            description: `Risk score ${r.risk_score}/100 (${r.severity_label}). MITRE: ${r.mitre_tactic ?? 'N/A'}. Auto-created by AI agent pipeline. Patch available: ${r.patch_available ? 'Yes' : 'No'}.`,
            severity:    r.severity_label?.toLowerCase() ?? 'high',
            status:      'open',
            assignee:    'Unassigned',
            created:     now,
            updatedAt:     now,
        })
        if (!error) summary.incidents++
        else console.error('[Supabase] Incident insert error:', error.message)
    }

    // ── 4. Save Playbooks ─────────────────────────────────────────────────
    const playbooks: any[] = result.playbooks ?? []
    for (const p of playbooks) {
        const { error } = await supabase.from('Playbook').insert({
            id:          `pb-agent-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
            title:       p.incident_title ?? `[AI] ${p.cve_id ?? 'Threat'} Response Playbook`,
            description: p.incident_summary ?? 'Auto-generated by CyberGuard AI Incident Response Agent',
            category:    'AI Generated',
            content:     p.playbook ?? {},
            cveId:       p.cve_id ?? null,
            lastUpdated: now,
            created:     now,
        })
        if (!error) summary.playbooks++
        else console.error('[Supabase] Playbook insert error:', error.message)
    }

    // ── 5. Save Reports ───────────────────────────────────────────────────
    const execReport = result.executive_report ?? {}
    const techReport = result.technical_report ?? {}
    const compReport = result.compliance_report ?? {}

    if (execReport.top_risk || techReport.total_findings) {
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
        else console.error('[Supabase] Report insert error:', error.message)
    }

    // ── 6. Mark job done in agent_jobs ────────────────────────────────────
    await supabase
        .from('agent_jobs')
        .update({ status: 'completed', completed_at: now })
        .eq('job_id', jobId)

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
                        threats:     result.threats      ?? [],
                        risk_scores: result.risk_register ?? [],
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
        console.warn('[API] Socket push failed (non-critical):', e)
    }
}


// ── Helpers ───────────────────────────────────────────────────────────────

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