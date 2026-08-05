import { ArrowUpRight, Check, Radio, Sparkles } from 'lucide-react'
import { useState } from 'react'
import type { Overview, SyncRun } from '../types'
import { formatRelativeTime } from '../lib/format'

interface RadarPanelProps {
  overview: Overview | null
  latestSync: SyncRun | null
  activeVendor: string
  onVendorSelect: (vendor: string) => void
}

const positions = [
  'left-[66%] top-[24%]', 'left-[27%] top-[32%]', 'left-[56%] top-[62%]',
  'left-[24%] top-[67%]', 'left-[73%] top-[53%]', 'left-[43%] top-[18%]',
  'left-[35%] top-[76%]', 'left-[78%] top-[70%]',
]

export function RadarPanel({ overview, latestSync, activeVendor, onVendorSelect }: RadarPanelProps) {
  const [hoveredVendor, setHoveredVendor] = useState('')
  const [expanded, setExpanded] = useState(false)
  const vendors = overview?.vendors ?? []
  const visibleVendors = vendors.slice(0, expanded ? 8 : 5)
  const maxValue = Math.max(...vendors.map((item) => item.value), 1)
  const focusVendor = hoveredVendor || activeVendor
  const focusRecord = vendors.find((item) => item.label === focusVendor)

  return (
    <aside className="space-y-4">
      <section className="radar-card relative overflow-hidden rounded-[22px] border border-white/[0.08] bg-[#101721]/85 p-5 shadow-lift">
        <div className="relative z-10 flex items-start justify-between">
          <div>
            <div className="eyebrow"><Radio size={13} /> Live relevance radar</div>
            <h2 className="mt-2 text-lg font-semibold tracking-tight text-white">厂商信号分布</h2>
            <p className="mt-1 text-[10px] text-slate-600">点击信号即可联动漏洞流</p>
          </div>
          <button
            type="button"
            className={`icon-button ${expanded ? 'border-signal/25 text-signal' : ''}`}
            aria-label={expanded ? '收起厂商详情' : '展开厂商详情'}
            aria-expanded={expanded}
            onClick={() => setExpanded((value) => !value)}
          >
            <ArrowUpRight size={16} className={`transition ${expanded ? 'rotate-90' : ''}`} />
          </button>
        </div>

        <div className="relative mx-auto my-6 aspect-square max-w-[220px]">
          <div className="radar-ring inset-[4%]" />
          <div className="radar-ring inset-[21%]" />
          <div className="radar-ring inset-[38%]" />
          <div className="absolute inset-1/2 h-px w-1/2 origin-left bg-gradient-to-r from-signal/80 to-transparent animate-sweep" />
          <div className="absolute inset-x-[12%] top-1/2 h-px bg-white/[0.06]" />
          <div className="absolute inset-y-[12%] left-1/2 w-px bg-white/[0.06]" />
          {visibleVendors.map((vendor, index) => {
            const active = vendor.label === activeVendor
            return (
              <button
                type="button"
                key={vendor.label}
                title={`${vendor.label}: ${vendor.value} 条漏洞`}
                aria-label={`筛选 ${vendor.label}，${vendor.value} 条漏洞`}
                aria-pressed={active}
                onClick={() => onVendorSelect(vendor.label)}
                onMouseEnter={() => setHoveredVendor(vendor.label)}
                onMouseLeave={() => setHoveredVendor('')}
                className={`absolute ${positions[index]} z-10 -m-2 grid h-7 w-7 place-items-center rounded-full transition duration-200 hover:scale-125 focus-visible:scale-125`}
              >
                <span
                  className={`block rounded-full border-2 border-[#111820] bg-signal shadow-[0_0_16px_rgba(201,242,122,.7)] transition-all ${active ? 'h-4 w-4 ring-4 ring-signal/15' : 'h-2.5 w-2.5'}`}
                  style={{ opacity: 0.55 + (vendor.value / maxValue) * 0.45 }}
                />
              </button>
            )
          })}
          <button
            type="button"
            onClick={() => activeVendor && onVendorSelect(activeVendor)}
            className="absolute inset-[38%] z-20 grid place-items-center rounded-full border border-signal/20 bg-[#162019]/90 text-center text-signal shadow-signal transition hover:scale-105"
            aria-label={activeVendor ? '清除厂商筛选' : '厂商雷达中心'}
          >
            {focusRecord ? (
              <span className="max-w-[58px] truncate px-1 text-[9px] font-semibold">
                {focusRecord.label}<small className="mt-0.5 block font-mono text-[8px] opacity-60">{focusRecord.value}</small>
              </span>
            ) : <Sparkles size={16} />}
          </button>
        </div>

        <div className="relative z-10 space-y-2">
          {visibleVendors.map((vendor) => {
            const active = vendor.label === activeVendor
            return (
              <button
                type="button"
                key={vendor.label}
                onClick={() => onVendorSelect(vendor.label)}
                onMouseEnter={() => setHoveredVendor(vendor.label)}
                onMouseLeave={() => setHoveredVendor('')}
                aria-pressed={active}
                className={`group flex w-full items-center gap-3 rounded-lg px-2 py-1.5 text-xs transition ${active ? 'bg-signal/[0.07]' : 'hover:bg-white/[0.035]'}`}
              >
                <span className={`w-20 truncate text-left ${active ? 'text-signal' : 'text-slate-400 group-hover:text-slate-200'}`}>{vendor.label}</span>
                <span className="h-1 flex-1 overflow-hidden rounded-full bg-white/[0.06]">
                  <span className="block h-full rounded-full bg-gradient-to-r from-signal/35 to-signal transition-[width] duration-500" style={{ width: `${Math.max(8, (vendor.value / maxValue) * 100)}%` }} />
                </span>
                <span className="w-8 text-right font-mono text-[10px] text-slate-600">{vendor.value}</span>
                <span className={`grid h-4 w-4 place-items-center rounded-full border ${active ? 'border-signal/30 bg-signal/10 text-signal' : 'border-white/[0.07] text-transparent'}`}><Check size={9} /></span>
              </button>
            )
          })}
          {!vendors.length && <p className="py-3 text-center text-xs text-slate-600">同步后显示厂商分布</p>}
        </div>
      </section>

      <section className="rounded-[22px] border border-white/[0.07] bg-white/[0.03] p-5">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-slate-500">最近更新</span>
          <span className={`h-2 w-2 rounded-full ${latestSync?.status === 'failed' ? 'bg-ember' : 'bg-signal animate-pulse-soft'}`} />
        </div>
        <div className="mt-3 text-sm font-medium text-slate-200">
          {latestSync?.status === 'running' ? '正在获取最新情报…' : formatRelativeTime(latestSync?.finished_at ?? null)}
        </div>
        <div className="mt-3 flex gap-4 border-t border-white/[0.06] pt-3 text-[11px] text-slate-600">
          <span>获取 {latestSync?.fetched_count ?? 0}</span>
          <span>相关 {latestSync?.relevant_count ?? 0}</span>
          <span className="ml-auto uppercase">{latestSync?.sources.join(' · ') || '等待首轮'}</span>
        </div>
      </section>
    </aside>
  )
}
