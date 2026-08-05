import { RefreshCw, Satellite, Settings2 } from 'lucide-react'
import { useCallback, useState } from 'react'
import { intelligenceApi } from './api/client'
import { AppShell } from './components/AppShell'
import { PolicyDrawer } from './components/PolicyDrawer'
import { RadarPanel } from './components/RadarPanel'
import { SignalOverview } from './components/SignalOverview'
import { IntelligenceAnalytics } from './components/IntelligenceAnalytics'
import { VulnerabilityDetail } from './components/VulnerabilityDetail'
import { VulnerabilityFeed } from './components/VulnerabilityFeed'
import { SemanticAnalysisWorkspace } from './components/SemanticAnalysisWorkspace'
import { SemanticModelDrawer } from './components/SemanticModelDrawer'
import { useIntelligence } from './hooks/useIntelligence'
import { formatRelativeTime } from './lib/format'
import type { IntelligenceFilters, Vulnerability } from './types'

const initialFilters: IntelligenceFilters = {
  query: '',
  vendor: '',
  severity: '',
  relevance: 'firmware',
  kevOnly: false,
  exploitOnly: false,
}

export function App() {
  const [filters, setFilters] = useState(initialFilters)
  const [selected, setSelected] = useState<Vulnerability | null>(null)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [syncStarting, setSyncStarting] = useState(false)
  const [syncError, setSyncError] = useState<string | null>(null)
  const [activeView, setActiveView] = useState<'intelligence' | 'semantic'>('intelligence')
  const [modelSettingsOpen, setModelSettingsOpen] = useState(false)
  const [semanticRefreshKey, setSemanticRefreshKey] = useState(0)
  const {
    overview, statistics, page, latestSync, loading, filtering, error, refresh,
    setCurrentPage,
  } = useIntelligence(filters)

  const toggleSignalFilter = (signal: 'all' | 'critical' | 'kev' | 'exploit') => {
    if (signal === 'all') {
      setFilters(initialFilters)
      return
    }
    if (signal === 'critical') {
      setFilters((current) => ({ ...current, severity: current.severity === 'CRITICAL' ? '' : 'CRITICAL' }))
    } else if (signal === 'kev') {
      setFilters((current) => ({ ...current, kevOnly: !current.kevOnly }))
    } else {
      setFilters((current) => ({ ...current, exploitOnly: !current.exploitOnly }))
    }
  }

  const startSync = useCallback(async () => {
    setSyncStarting(true)
    setSyncError(null)
    try {
      await intelligenceApi.sync(1)
      window.setTimeout(() => void refresh(), 250)
    } catch (caught) {
      setSyncError(caught instanceof Error ? caught.message : '启动更新失败')
    } finally {
      setSyncStarting(false)
    }
  }, [refresh])

  const syncing = syncStarting || latestSync?.status === 'running'

  return (
    <AppShell
      onOpenSettings={() => setSettingsOpen(true)}
      activeView={activeView}
      onNavigate={setActiveView}
    >
      {activeView === 'semantic' ? (
        <SemanticAnalysisWorkspace
          key={semanticRefreshKey}
          onConfigureModel={() => setModelSettingsOpen(true)}
        />
      ) : (
      <>
      {/*
        Design rationale: a dense intelligence console still needs calm hierarchy.
        The dark atlas-like grid, acid signal color and restrained glass surfaces
        distinguish evidence, live state and risk without turning the page into a neon dashboard.
      */}
      <header className="mb-7 flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="eyebrow">
            <Satellite size={13} /> Firmware intelligence / Live desk
          </div>
          <h1 className="mt-3 text-[30px] font-semibold leading-none tracking-[-0.045em] text-white sm:text-[38px]">
            漏洞情报工作台
          </h1>
          <p className="mt-3 max-w-2xl text-xs leading-6 text-slate-500 sm:text-sm">
            从官方来源捕获变化，用可解释信号筛出真正与固件相关的漏洞。
            <span className="ml-2 text-slate-700">
              {formatRelativeTime(overview?.last_updated ?? null)}更新
            </span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setSettingsOpen(true)}
            className="hidden h-10 items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.025] px-3.5 text-xs text-slate-400 transition hover:border-white/15 hover:text-white sm:flex lg:hidden xl:flex"
          >
            <Settings2 size={15} /> 判定策略
          </button>
          <button
            type="button"
            onClick={() => void startSync()}
            disabled={syncing}
            className="flex h-10 items-center gap-2 rounded-xl bg-signal px-4 text-xs font-semibold text-[#11170a] shadow-signal transition hover:-translate-y-0.5 hover:brightness-105 disabled:translate-y-0 disabled:cursor-wait disabled:opacity-60"
          >
            <RefreshCw size={15} className={syncing ? 'animate-spin' : ''} />
            {syncing ? '正在更新' : '获取最新情报'}
          </button>
        </div>
      </header>

      {(error || syncError) && (
        <div role="alert" className="mb-5 flex items-center justify-between rounded-xl border border-ember/15 bg-ember/[0.055] px-4 py-3 text-xs text-ember">
          <span>情报服务暂不可用：{error || syncError}</span>
          <button type="button" onClick={() => void refresh()} className="font-semibold underline underline-offset-4">重试</button>
        </div>
      )}

      <SignalOverview
        overview={overview}
        loading={loading}
        activeSignal={filters.severity === 'CRITICAL' ? 'critical' : filters.kevOnly ? 'kev' : filters.exploitOnly ? 'exploit' : null}
        onSignalSelect={toggleSignalFilter}
      />

      <IntelligenceAnalytics statistics={statistics} loading={loading} />

      <div className="mt-4 grid items-start gap-4 2xl:grid-cols-[minmax(0,1fr)_320px]">
        <VulnerabilityFeed
          page={page}
          filters={filters}
          onFiltersChange={setFilters}
          onSelect={setSelected}
          onPageChange={setCurrentPage}
          loading={loading}
          filtering={filtering}
          vendors={overview?.vendors ?? []}
        />
        <RadarPanel
          overview={overview}
          latestSync={latestSync}
          activeVendor={filters.vendor}
          onVendorSelect={(vendor) => setFilters((current) => ({
            ...current,
            vendor: current.vendor === vendor ? '' : vendor,
          }))}
        />
      </div>

      <VulnerabilityDetail vulnerability={selected} onClose={() => setSelected(null)} />
      <PolicyDrawer
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        onSaved={() => void refresh()}
      />
      </>
      )}
      <SemanticModelDrawer
        open={modelSettingsOpen}
        onClose={() => setModelSettingsOpen(false)}
        onSaved={() => setSemanticRefreshKey((value) => value + 1)}
      />
    </AppShell>
  )
}
