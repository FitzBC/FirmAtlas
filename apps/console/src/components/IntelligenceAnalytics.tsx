import { BarChart3, CalendarRange, Layers3, ShieldEllipsis } from 'lucide-react'
import type { IntelligenceStatistics } from '../types'
import { formatCompactNumber } from '../lib/format'

interface Props {
  statistics: IntelligenceStatistics | null
  loading: boolean
}

const severityColors: Record<string, string> = {
  CRITICAL: '#ff8a65',
  HIGH: '#ffbd74',
  MEDIUM: '#75d6ff',
  LOW: '#c9f27a',
  UNKNOWN: '#475569',
}

export function IntelligenceAnalytics({ statistics, loading }: Props) {
  const severity = statistics?.severity ?? []
  const totalSeverity = severity.reduce((sum, item) => sum + item.value, 0) || 1
  const maxCwe = Math.max(...(statistics?.cwes.map((item) => item.value) ?? [1]), 1)
  const years = statistics?.years ?? []
  const maxYear = Math.max(...years.map((item) => item.value), 1)
  const points = years
    .map((item, index) => {
      const x = years.length === 1 ? 50 : (index / Math.max(years.length - 1, 1)) * 100
      const y = 35 - (item.value / maxYear) * 29
      return `${x},${y}`
    })
    .join(' ')

  return (
    <section className="mt-4 grid gap-3 lg:grid-cols-[1.1fr_1fr_1.15fr]">
      <article className="analytics-card">
        <AnalyticsTitle icon={<ShieldEllipsis size={14} />} title="风险与评分标准" meta="CVSS BASE" />
        {loading ? <Skeleton /> : (
          <>
            <div className="mt-5 flex h-2 overflow-hidden rounded-full bg-white/[0.04]">
              {severity.map((item) => (
                <div key={item.label} style={{ width: `${(item.value / totalSeverity) * 100}%`, background: severityColors[item.label] ?? severityColors.UNKNOWN }} />
              ))}
            </div>
            <div className="mt-4 grid grid-cols-2 gap-x-5 gap-y-2">
              {severity.slice(0, 4).map((item) => (
                <div key={item.label} className="flex items-center justify-between text-[10px]">
                  <span className="flex items-center gap-2 text-slate-600"><i className="h-1.5 w-1.5 rounded-full" style={{ background: severityColors[item.label] ?? severityColors.UNKNOWN }} />{item.label}</span>
                  <strong className="font-mono font-medium text-slate-300">{formatCompactNumber(item.value)}</strong>
                </div>
              ))}
            </div>
            <div className="mt-4 flex flex-wrap gap-1.5 border-t border-white/[0.06] pt-3">
              {(statistics?.cvss_versions ?? []).slice(0, 4).map((item) => (
                <span key={item.label} className="rounded-md bg-white/[0.035] px-2 py-1 text-[9px] text-slate-600">v{item.label} <b className="ml-1 text-slate-400">{formatCompactNumber(item.value)}</b></span>
              ))}
            </div>
          </>
        )}
      </article>

      <article className="analytics-card">
        <AnalyticsTitle icon={<Layers3 size={14} />} title="高频弱点类型" meta="TOP CWE" />
        {loading ? <Skeleton /> : (
          <div className="mt-4 space-y-2.5">
            {(statistics?.cwes ?? []).slice(0, 5).map((item) => (
              <div key={item.label} className="grid grid-cols-[62px_1fr_36px] items-center gap-2 text-[10px]">
                <a href={`https://cwe.mitre.org/data/definitions/${item.label.replace('CWE-', '')}.html`} target="_blank" rel="noreferrer" className="font-mono text-cyan hover:underline">{item.label}</a>
                <div className="h-1 overflow-hidden rounded-full bg-white/[0.05]"><div className="h-full rounded-full bg-cyan/70" style={{ width: `${(item.value / maxCwe) * 100}%` }} /></div>
                <span className="text-right font-mono text-slate-500">{item.value}</span>
              </div>
            ))}
            {!statistics?.cwes.length && <Empty label="等待 CWE 数据" />}
          </div>
        )}
      </article>

      <article className="analytics-card">
        <AnalyticsTitle icon={<CalendarRange size={14} />} title="固件漏洞年度趋势" meta="12 YEARS" />
        {loading ? <Skeleton /> : years.length ? (
          <div className="mt-3">
            <svg viewBox="0 0 100 40" className="h-[82px] w-full overflow-visible" preserveAspectRatio="none" aria-label="年度漏洞趋势">
              <defs><linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#c9f27a" stopOpacity=".28" /><stop offset="1" stopColor="#c9f27a" stopOpacity="0" /></linearGradient></defs>
              <polygon points={`0,40 ${points} 100,40`} fill="url(#trendFill)" />
              <polyline points={points} fill="none" stroke="#c9f27a" strokeWidth="1.2" vectorEffect="non-scaling-stroke" />
            </svg>
            <div className="mt-1 flex justify-between text-[9px] text-slate-700"><span>{years[0]?.label}</span><strong className="font-mono text-signal">峰值 {formatCompactNumber(maxYear)}</strong><span>{years.at(-1)?.label}</span></div>
          </div>
        ) : <Empty label="等待年度数据" />}
      </article>
    </section>
  )
}

function AnalyticsTitle({ icon, title, meta }: { icon: React.ReactNode; title: string; meta: string }) {
  return <div className="flex items-center justify-between"><h2 className="flex items-center gap-2 text-[11px] font-semibold text-slate-300">{icon}{title}</h2><span className="text-[8px] font-semibold tracking-[0.15em] text-slate-700">{meta}</span></div>
}

function Skeleton() {
  return <div className="mt-5 space-y-3 animate-pulse"><div className="h-2 rounded bg-white/[0.06]" /><div className="h-14 rounded bg-white/[0.035]" /></div>
}

function Empty({ label }: { label: string }) {
  return <div className="grid min-h-20 place-items-center text-[10px] text-slate-700"><BarChart3 size={16} className="mb-2" />{label}</div>
}
