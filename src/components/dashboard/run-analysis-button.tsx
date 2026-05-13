'use client'

import { useState, useEffect, useRef } from 'react'
import { Bot, Zap, CheckCircle2, XCircle, Loader2, ChevronDown, Shield } from 'lucide-react'

type Phase = 'idle' | 'starting' | 'polling' | 'done' | 'error'

interface StepStatus {
    label: string
    status: 'waiting' | 'running' | 'done' | 'error'
}

const PIPELINE_STEPS = [
    'Threat Intelligence',
    'Vulnerability Assessment',
    'Risk Scoring',
    'Incident Response',
    'Reporting',
]

const SAMPLE_INDICATORS = [
    { type: 'cve', value: 'CVE-2021-44228', source: 'NVD', confidence: 100 },
    { type: 'ip', value: '45.33.32.156', source: 'OTX', confidence: 85 },
    { type: 'domain', value: 'malicious-c2-server.com', source: 'ThreatFox', confidence: 75 },
]

const SAMPLE_ASSETS = [
    {
        id: 'asset-001',
        name: 'Production Web Server',
        ip_address: '10.0.1.10',
        os: 'Ubuntu 22.04',
        software: [{ name: 'Apache Log4j', version: '2.14.0' }],
        criticality: 'CRITICAL',
        network_exposure: 'internet-facing',
    },
    {
        id: 'asset-002',
        name: 'Internal Database',
        ip_address: '10.0.1.20',
        os: 'Ubuntu 22.04',
        software: [{ name: 'PostgreSQL', version: '14.5' }],
        criticality: 'HIGH',
        network_exposure: 'internal',
    },
]

export function RunAnalysisButton() {
    const [phase, setPhase] = useState<Phase>('idle')
    const [jobId, setJobId] = useState<string | null>(null)
    const [steps, setSteps] = useState<StepStatus[]>(
        PIPELINE_STEPS.map(label => ({ label, status: 'waiting' }))
    )
    const [result, setResult] = useState<any>(null)
    const [errorMsg, setErrorMsg] = useState<string>('')
    const [expanded, setExpanded] = useState(false)
    const [elapsed, setElapsed] = useState(0)
    const timerRef = useRef<NodeJS.Timeout | null>(null)

    useEffect(() => {
        if (phase === 'starting' || phase === 'polling') {
            timerRef.current = setInterval(() => setElapsed(e => e + 1), 1000)
        } else {
            if (timerRef.current) clearInterval(timerRef.current)
            if (phase === 'idle') setElapsed(0)
        }
        return () => { if (timerRef.current) clearInterval(timerRef.current) }
    }, [phase])

    useEffect(() => {
        if (phase !== 'polling') return
        const stepIndex = Math.min(Math.floor(elapsed / 4), PIPELINE_STEPS.length - 1)
        setSteps(prev => prev.map((s, i) => ({
            ...s,
            status: i < stepIndex ? 'done' : i === stepIndex ? 'running' : 'waiting',
        })))
    }, [elapsed, phase])

    async function startAnalysis() {
        setPhase('starting')
        setSteps(PIPELINE_STEPS.map(label => ({ label, status: 'waiting' })))
        setResult(null)
        setErrorMsg('')
        setExpanded(true)

        try {
            setPhase('polling') // Start UI animation timer
            
            // Send request and WAIT for Groq + Supabase to finish saving
            const res = await fetch('/api/threats', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    indicators: SAMPLE_INDICATORS,
                    assets: SAMPLE_ASSETS,
                }),
            })

            const data = await res.json()

            if (!res.ok || !data.success) {
                throw new Error(data.error || `HTTP Error ${res.status}`)
            }

            const job = data.job
            setJobId(data.job_id)

            if (job?.status === 'completed') {
                setSteps(PIPELINE_STEPS.map(label => ({ label, status: 'done' })))
                setResult(job.result)
                setPhase('done')
            } else {
                throw new Error('Pipeline returned unexpected status')
            }

        } catch (err: any) {
            setErrorMsg(err.message)
            setPhase('error')
        }
    }

    function reset() {
        setPhase('idle')
        setJobId(null)
        setResult(null)
        setErrorMsg('')
        setExpanded(false)
        setSteps(PIPELINE_STEPS.map(label => ({ label, status: 'waiting' })))
    }

    const isRunning = phase === 'starting' || phase === 'polling'

    return (
        <div className="w-full rounded-xl border border-slate-700/60 bg-slate-900/60 backdrop-blur-sm p-4">
            {/* ── Trigger Button ── */}
            <div className="flex flex-wrap items-center gap-3">
                <button
                    onClick={isRunning ? undefined : phase === 'done' || phase === 'error' ? reset : startAnalysis}
                    disabled={isRunning}
                    className={`
                        inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium
                        transition-all duration-200 border
                        ${isRunning
                            ? 'bg-primary/10 border-primary/30 text-primary cursor-not-allowed'
                            : phase === 'done'
                                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20 cursor-pointer'
                                : phase === 'error'
                                    ? 'bg-red-500/10 border-red-500/30 text-red-400 hover:bg-red-500/20 cursor-pointer'
                                    : 'bg-primary border-primary/80 text-primary-foreground hover:bg-primary/90 cursor-pointer'
                        }
                    `}
                >
                    {isRunning ? (
                        <><Loader2 className="w-4 h-4 animate-spin" /> Running… {elapsed}s</>
                    ) : phase === 'done' ? (
                        <><CheckCircle2 className="w-4 h-4" /> Analysis Complete — Run Again</>
                    ) : phase === 'error' ? (
                        <><XCircle className="w-4 h-4" /> Failed — Retry</>
                    ) : (
                        <><Bot className="w-4 h-4" /> Run AI Analysis</>
                    )}
                </button>

                {(isRunning || phase === 'done' || phase === 'error') && (
                    <button
                        onClick={() => setExpanded(e => !e)}
                        className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 transition-colors"
                    >
                        {expanded ? 'Hide' : 'Show'} details
                        <ChevronDown className={`w-3 h-3 transition-transform ${expanded ? 'rotate-180' : ''}`} />
                    </button>
                )}
            </div>

            {/* ── Pipeline Progress Panel ── */}
            {expanded && (
                <div className="mt-4 rounded-xl border border-slate-700/60 bg-slate-900/80 backdrop-blur-sm overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700/40">
                        <div className="flex items-center gap-2">
                            <Shield className="w-4 h-4 text-emerald-400" />
                            <span className="text-sm font-medium text-slate-200">
                                AI Pipeline
                            </span>
                        </div>
                        {jobId && (
                            <span className="text-xs text-slate-500 font-mono">{jobId}</span>
                        )}
                    </div>

                    <div className="px-4 py-3 grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-2">
                        {steps.map((step, i) => (
                            <div
                                key={step.label}
                                className={`rounded-lg border px-3 py-2 ${step.status === 'done'
                                    ? 'border-emerald-500/30 bg-emerald-500/5'
                                    : step.status === 'running'
                                        ? 'border-emerald-500/30 bg-emerald-500/5'
                                        : step.status === 'error'
                                            ? 'border-red-500/30 bg-red-500/5'
                                            : 'border-slate-700/60 bg-slate-800/40'
                                    }`}
                            >
                                <div className="flex items-center justify-between gap-2">
                                    <span className="text-[11px] font-mono text-slate-400">Agent {i + 1}</span>
                                    {step.status === 'done' ? (
                                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                                    ) : step.status === 'running' ? (
                                        <Loader2 className="w-3.5 h-3.5 text-emerald-400 animate-spin" />
                                    ) : step.status === 'error' ? (
                                        <XCircle className="w-3.5 h-3.5 text-red-400" />
                                    ) : (
                                        <div className="w-3.5 h-3.5 rounded-full border border-slate-600" />
                                    )}
                                </div>
                                <p className="mt-1 text-xs text-slate-200 truncate">{step.label}</p>
                            </div>
                        ))}
                    </div>

                    {phase === 'error' && (
                        <div className="mx-4 mb-3 px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/20">
                            <p className="text-xs text-red-400 wrap-break-word">{errorMsg}</p>
                        </div>
                    )}

                    {phase === 'done' && result && (
                        <div className="mx-4 mb-3 px-3 py-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20 space-y-2">
                            {result.executive_report && (
                                <>
                                    <div className="flex items-center justify-between">
                                        <span className="text-xs text-slate-400">Posture Score</span>
                                        <span className={`text-sm font-bold ${result.executive_report.posture_score >= 70 ? 'text-emerald-400' :
                                            result.executive_report.posture_score >= 40 ? 'text-yellow-400' :
                                                'text-red-400'
                                            }`}>
                                            {result.executive_report.posture_score}/100
                                        </span>
                                    </div>
                                    <div className="flex gap-3 text-xs">
                                        {Object.entries(result.executive_report.severity_summary || {}).map(([k, v]) => (
                                            <span key={k} className={`
                                                ${k === 'critical' ? 'text-red-400' :
                                                    k === 'high' ? 'text-orange-400' :
                                                        k === 'medium' ? 'text-yellow-400' :
                                                            'text-green-400'}
                                            `}>
                                                {String(v)} {k}
                                            </span>
                                        ))}
                                    </div>
                                    {result.executive_report.top_risk && (
                                        <p className="text-xs text-slate-300 border-t border-slate-700/40 pt-2">
                                            ⚠ {result.executive_report.top_risk}
                                        </p>
                                    )}
                                    {result.executive_report.action_required && (
                                        <p className="text-xs text-emerald-300">
                                            → {result.executive_report.action_required}
                                        </p>
                                    )}
                                </>
                            )}
                        </div>
                    )}

                    <div className="px-4 py-2 border-t border-slate-700/40 flex items-center justify-between">
                        <div className="flex items-center gap-1">
                            <Zap className="w-3 h-3 text-slate-500" />
                            <span className="text-xs text-slate-500">
                                {phase === 'done' ? `Completed in ${elapsed}s` :
                                    phase === 'error' ? `Failed after ${elapsed}s` :
                                        `Running for ${elapsed}s`}
                            </span>
                        </div>
                        <span className="text-xs text-slate-600">
                            Groq · llama-3.3-70b-versatile
                        </span>
                    </div>
                </div>
            )}
        </div>
    )
}