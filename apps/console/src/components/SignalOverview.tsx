import { Activity, Crosshair, FlaskConical, ShieldAlert } from 'lucide-react'
import type { Overview } from '../types'
import { formatCompactNumber } from '../lib/format'

interface SignalOverviewProps {
  overview: Overview | null
  loading: boolean
  activeSignal: 'critical' | 'kev' | 'exploit' | null
  onSignalSelect: (signal: 'all' | 'critical' | 'kev' | 'exploit') => void
}

export function SignalOverview({ overview, loading, activeSignal, onSignalSelect }: SignalOverviewProps) {
  const counts = overview?.counts ?? { relevant: 0, critical: 0, kev: 0, exploit: 0 }
  const stats = [
    { label: '固件相关', value: counts.relevant, icon: Crosshair, tone: 'signal', signal: 'all' },
    { label: '严重漏洞', value: counts.critical, icon: ShieldAlert, tone: 'ember', signal: 'critical' },
    { label: '已知利用', value: counts.kev, icon: Activity, tone: 'cyan', signal: 'kev' },
    { label: 'EXP / PoC', value: counts.exploit, icon: FlaskConical, tone: 'violet', signal: 'exploit' },
  ] as const

  return (
    <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
      {stats.map(({ label, value, icon: Icon, tone, signal }, index) => (
        <button
          type="button"
          key={label}
          onClick={() => onSignalSelect(signal)}
          aria-pressed={signal !== 'all' && activeSignal === signal}
          className={`group relative overflow-hidden rounded-2xl border bg-white/[0.035] p-4 text-left transition duration-300 hover:-translate-y-0.5 hover:border-white/[0.16] sm:p-5 ${signal !== 'all' && activeSignal === signal ? 'border-signal/30 ring-1 ring-signal/10' : 'border-white/[0.07]'}`}
          style={{ animationDelay: `${index * 60}ms` }}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-500">{label}</span>
            <div className={`tone-${tone} rounded-lg p-1.5`}>
              <Icon size={15} />
            </div>
          </div>
          <div className="mt-4 flex items-end gap-2">
            <strong className="text-2xl font-semibold tracking-[-0.04em] text-white sm:text-3xl">
              {loading ? '—' : formatCompactNumber(value)}
            </strong>
            <span className="mb-1 text-[10px] uppercase tracking-wider text-slate-600">records</span>
          </div>
          <div className="absolute -bottom-8 -right-6 h-20 w-20 rounded-full bg-white/[0.025] blur-xl transition group-hover:bg-white/[0.05]" />
        </button>
      ))}
    </div>
  )
}
