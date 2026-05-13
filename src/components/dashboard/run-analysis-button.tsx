'use client'

import { useEffect, useRef, useState } from 'react'
import { Bot, Zap, CheckCircle2, XCircle, Loader2, ChevronDown, Shield } from 'lucide-react'

type Phase = 'idle' | 'loading' | 'done' | 'error'

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

function createInitialSteps(): StepStatus[] {
    return PIPELINE_STEPS.map(label => ({ label, status: 'waiting' }))
}

export function RunAnalysisButton() {
    const [phase, setPhase] = useState<Phase>('idle')
    const [steps, setSteps] = useState<StepStatus[]>(createInitialSteps())
    const [result, setResult] = useState<any>(null)
    const [errorMsg, setErrorMsg] = useState<string>('')
    const [expanded, setExpanded] = useState(false)
    const [elapsed, setElapsed] = useState(0)
    const [jobId, setJobId] = useState<string | null>(null)
    const timerRef = useRef<NodeJS.Timeout | null>(null)

    useEffect(() => {
        if (phase !== 'loading') {
            if (timerRef.current) {
                clearInterval(timerRef.current)
                timerRef.current = null
            }
            return
        }

        timerRef.current = setInterval(() => {
            setElapsed(current => current + 1)
        }, 1000)

        return () => {
            if (timerRef.current) {
                clearInterval(timerRef.current)
                timerRef.current = null
            }
        }
    }, [phase])

    useEffect(() => {
        if (phase === 'idle') {
            setElapsed(0)
            setSteps(createInitialSteps())
            return
        }

        if (phase === 'done') {
            setSteps(PIPELINE_STEPS.map(label => ({ label, status: 'done' })))
            return
        }

        if (phase === 'error') {
            setSteps(prev => prev.map((step, index) => ({
                ...step,
                status: index === 0 ? 'error' : 'waiting',
            })))
            return
        }

        const stepIndex = Math.min(Math.floor(elapsed / 2), PIPELINE_STEPS.length - 1)
        setSteps(prev => prev.map((step, index) => ({
            ...step,
            status: index < stepIndex ? 'done' : index === stepIndex ? 'running' : 'waiting',
        })))
    }, [elapsed, phase])

    async function startAnalysis() {
        setPhase('loading')
        setElapsed(0)
        setSteps(createInitialSteps())
        setResult(null)
        setErrorMsg('')
        setExpanded(true)

        try {
            const response = await fetch('/api/threats', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    indicators: SAMPLE_INDICATORS,
                    assets: SAMPLE_ASSETS,
                }),
            })

            const data = await response.json()

            if (!response.ok || !data?.success) {
                throw new Error(data?.error || `HTTP Error ${response.status}`)
            }

            setJobId(data?.job_id ?? null)
            setResult(data?.job?.result ?? null)
            setSteps(PIPELINE_STEPS.map(label => ({ label, status: 'done' })))
            setPhase('done')
        } catch (error: any) {
            setErrorMsg(error?.message ?? 'Analysis failed')
            setPhase('error')
        }
    }

    function reset() {
        setPhase('idle')
        setJobId(null)
        setResult(null)
        setErrorMsg('')
        setExpanded(false)
        setElapsed(0)
        setSteps(createInitialSteps())
    }

    const isRunning = phase === 'loading'
    const postureScore = result?.executive_report?.posture_score ?? 'N/A'
    const severitySummary = result?.executive_report?.severity_summary ?? {}
    const topRisk = result?.executive_report?.top_risk ?? 'N/A'
    const actionRequired = result?.executive_report?.action_required ?? 'N/A'
    const postureScoreNumber = typeof result?.executive_report?.posture_score === 'number'
        ? result.executive_report.posture_score
        : null

    return (
        <div className="w-full rounded-xl border border-slate-700/60 bg-slate-900/60 backdrop-blur-sm p-4">
            <div className="flex flex-wrap items-center gap-3">
                <button
                    onClick={isRunning ? undefined : phase === 'done' || phase === 'error' ? reset : startAnalysis}
                    disabled={isRunning}
                    className={`
                        inline-flex items-center gap-2 rounded-lg border px-4 py-2 text-sm font-medium transition-all duration-200
                        ${isRunning
                            ? 'cursor-not-allowed border-primary/30 bg-primary/10 text-primary'
                            : phase === 'done'
                                ? 'cursor-pointer border-emerald-500/30 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20'
                                : phase === 'error'
                                    ? 'cursor-pointer border-red-500/30 bg-red-500/10 text-red-400 hover:bg-red-500/20'
                                    : 'cursor-pointer border-primary/80 bg-primary text-primary-foreground hover:bg-primary/90'
                        }
                    `}
                >
                    {isRunning ? (
                        <><Loader2 className="h-4 w-4 animate-spin" /> Running… {elapsed}s</>
                    ) : phase === 'done' ? (
                        <><CheckCircle2 className="h-4 w-4" /> Analysis Complete — Run Again</>
                    ) : phase === 'error' ? (
                        <><XCircle className="h-4 w-4" /> Failed — Retry</>
                    ) : (
                        <><Bot className="h-4 w-4" /> Run AI Analysis</>
                    )}
                </button>

                {(isRunning || phase === 'done' || phase === 'error') && (
                    <button
                        onClick={() => setExpanded(current => !current)}
                        className="inline-flex items-center gap-1 text-xs text-slate-400 transition-colors hover:text-slate-200"
                    >
                        {expanded ? 'Hide' : 'Show'} details
                        <ChevronDown className={`h-3 w-3 transition-transform ${expanded ? 'rotate-180' : ''}`} />
                    </button>
                )}
            </div>

            {expanded && (
                <div className="mt-4 overflow-hidden rounded-xl border border-slate-700/60 bg-slate-900/80 backdrop-blur-sm">
                    <div className="flex items-center justify-between border-b border-slate-700/40 px-4 py-3">
                        <div className="flex items-center gap-2">
                            <Shield className="h-4 w-4 text-emerald-400" />
                            <span className="text-sm font-medium text-slate-200">AI Pipeline</span>
                        </div>
                        {jobId && <span className="font-mono text-xs text-slate-500">{jobId}</span>}
                    </div>

                    <div className="grid grid-cols-1 gap-2 px-4 py-3 sm:grid-cols-2 xl:grid-cols-5">
                        {steps.map((step, index) => (
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
                                    <span className="font-mono text-[11px] text-slate-400">Agent {index + 1}</span>
                                    {step.status === 'done' ? (
                                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                                    ) : step.status === 'running' ? (
                                        <Loader2 className="h-3.5 w-3.5 animate-spin text-emerald-400" />
                                    ) : step.status === 'error' ? (
                                        <XCircle className="h-3.5 w-3.5 text-red-400" />
                                    ) : (
                                        <div className="h-3.5 w-3.5 rounded-full border border-slate-600" />
                                    )}
                                </div>
                                <p className="mt-1 truncate text-xs text-slate-200">{step.label}</p>
                            </div>
                        ))}
                    </div>

                    {phase === 'error' && (
                        <div className="mx-4 mb-3 rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2">
                            <p className="break-words text-xs text-red-400">{errorMsg ?? 'Analysis failed'}</p>
                        </div>
                    )}

                    {phase === 'done' && (
                        <div className="mx-4 mb-3 space-y-2 rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-3 py-3">
                            <div className="flex items-center justify-between">
                                <span className="text-xs text-slate-400">Posture Score</span>
                                <span className={`text-sm font-bold ${typeof postureScoreNumber === 'number'
                                    ? postureScoreNumber >= 70
                                        ? 'text-emerald-400'
                                        : postureScoreNumber >= 40
                                            ? 'text-yellow-400'
                                            : 'text-red-400'
                                    : 'text-slate-300'
                                    }`}>
                                    {postureScore ?? 'N/A'}
                                </span>
                            </div>
                            <div className="flex flex-wrap gap-3 text-xs">
                                {Object.entries(severitySummary ?? {}).map(([key, value]) => (
                                    <span
                                        key={key}
                                        className={
                                            key === 'critical'
                                                ? 'text-red-400'
                                                : key === 'high'
                                                    ? 'text-orange-400'
                                                    : key === 'medium'
                                                        ? 'text-yellow-400'
                                                        : 'text-green-400'
                                        }
                                    >
                                        {String(value)} {key}
                                    </span>
                                ))}
                            </div>
                            <p className="border-t border-slate-700/40 pt-2 text-xs text-slate-300">
                                ⚠ {topRisk ?? 'N/A'}
                            </p>
                            <p className="text-xs text-emerald-300">
                                → {actionRequired ?? 'N/A'}
                            </p>
                        </div>
                    )}

                    <div className="flex items-center justify-between border-t border-slate-700/40 px-4 py-2">
                        <div className="flex items-center gap-1">
                            <Zap className="h-3 w-3 text-slate-500" />
                            <span className="text-xs text-slate-500">
                                {phase === 'done'
                                    ? `Completed in ${elapsed}s`
                                    : phase === 'error'
                                        ? `Failed after ${elapsed}s`
                                        : `Running for ${elapsed}s`}
                            </span>
                        </div>
                        <span className="text-xs text-slate-600">Synchronous AI Pipeline</span>
                    </div>
                </div>
            )}
        </div>
    )
}