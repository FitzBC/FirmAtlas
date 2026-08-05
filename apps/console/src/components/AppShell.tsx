import {
  Boxes,
  ChevronLeft,
  CircleDot,
  FileSearch,
  Gauge,
  RadioTower,
  Settings2,
  ShieldCheck,
} from 'lucide-react'
import type { ReactNode } from 'react'

interface AppShellProps {
  children: ReactNode
  onOpenSettings: () => void
  activeView: 'intelligence' | 'semantic'
  onNavigate: (view: 'intelligence' | 'semantic') => void
}

const navigation = [
  { label: '态势总览', icon: Gauge, view: null },
  { label: '漏洞情报', icon: RadioTower, view: 'intelligence' as const },
  { label: '固件资产', icon: Boxes, view: null },
  { label: '语义洞察', icon: FileSearch, view: 'semantic' as const },
]

export function AppShell({ children, onOpenSettings, activeView, onNavigate }: AppShellProps) {
  return (
    <div className="min-h-screen bg-ink text-slate-100">
      <div className="ambient-grid" aria-hidden="true" />
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-[248px] border-r border-white/[0.07] bg-[#090d14]/90 px-5 py-6 backdrop-blur-xl lg:flex lg:flex-col">
        <Brand />
        <nav className="mt-11 space-y-1" aria-label="主导航">
          {navigation.map(({ label, icon: Icon, view }) => {
            const active = view === activeView
            return (
            <button
              key={label}
              type="button"
              onClick={() => view && onNavigate(view)}
              disabled={!view}
              className={`group flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition ${
                active
                  ? 'bg-white/[0.08] text-white shadow-inner shadow-white/[0.03]'
                  : view ? 'text-slate-500 hover:bg-white/[0.04] hover:text-slate-200' : 'cursor-default text-slate-700'
              }`}
            >
              <Icon
                size={17}
                className={active ? 'text-signal' : 'transition group-hover:text-slate-300'}
              />
              <span>{label}</span>
              {active && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-signal shadow-signal" />}
            </button>
          )})}
        </nav>
        <div className="mt-auto">
          <div className="mb-5 rounded-2xl border border-white/[0.07] bg-gradient-to-br from-white/[0.06] to-transparent p-4">
            <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.18em] text-slate-500">
              <ShieldCheck size={14} className="text-cyan" />
              Evidence mode
            </div>
            <p className="mt-3 text-sm leading-6 text-slate-300">
              所有相关性判断均保留来源与可解释信号。
            </p>
          </div>
          <button
            type="button"
            onClick={onOpenSettings}
            className="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-slate-500 transition hover:bg-white/[0.04] hover:text-slate-200"
          >
            <Settings2 size={17} />
            相关性策略
          </button>
        </div>
      </aside>

      <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-white/[0.07] bg-[#080b11]/80 px-5 backdrop-blur-2xl lg:hidden">
        <Brand compact />
        <button
          type="button"
          onClick={onOpenSettings}
          aria-label="打开相关性策略"
          className="rounded-xl border border-white/10 p-2 text-slate-400"
        >
          <Settings2 size={18} />
        </button>
      </header>

      <main className="relative z-10 lg:pl-[248px]">
        <div className="mx-auto max-w-[1540px] px-5 py-7 sm:px-7 lg:px-10 lg:py-9">
          {children}
        </div>
      </main>
    </div>
  )
}

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-3">
      <div className="relative grid h-9 w-9 place-items-center overflow-hidden rounded-xl border border-signal/20 bg-signal/[0.08]">
        <CircleDot size={18} className="text-signal" />
        <span className="absolute inset-x-1 top-1/2 h-px rotate-[-30deg] bg-signal/40" />
      </div>
      <div>
        <div className="flex items-center gap-1.5 text-[15px] font-semibold tracking-[-0.02em] text-white">
          FirmAtlas
          {!compact && <ChevronLeft size={12} className="rotate-180 text-slate-700" />}
        </div>
        <div className="mt-0.5 text-[9px] font-semibold uppercase tracking-[0.24em] text-slate-600">
          Intelligence OS
        </div>
      </div>
    </div>
  )
}
