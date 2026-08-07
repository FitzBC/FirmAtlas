import {
  Activity, ArrowRight, Braces, BrainCircuit, Cable, CheckCircle2,
  CircleDotDashed, Clock3, DatabaseZap, KeyRound, LoaderCircle, Play,
  Route, ScanSearch, Sparkles, LayoutDashboard, ListTree, Waypoints,
} from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { intelligenceApi } from '../api/client'
import type { SemanticJob, SemanticModelSettings, SemanticOverview } from '../types'
import { formatCompactNumber, formatRelativeTime } from '../lib/format'
import { SemanticExplorer } from './SemanticExplorer'

interface SemanticAnalysisWorkspaceProps {
  onConfigureModel: () => void
}

export function SemanticAnalysisWorkspace({ onConfigureModel }: SemanticAnalysisWorkspaceProps) {
  const [overview, setOverview] = useState<SemanticOverview | null>(null)
  const [job, setJob] = useState<SemanticJob | null>(null)
  const [settings, setSettings] = useState<SemanticModelSettings | null>(null)
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [section, setSection] = useState<'overview' | 'interface' | 'parameter' | 'category'>('overview')

  const load = useCallback(async () => {
    try {
      const [nextOverview, nextJob, nextSettings] = await Promise.all([
        intelligenceApi.semanticOverview(),
        intelligenceApi.semanticLatestJob(),
        intelligenceApi.semanticSettings(),
      ])
      setOverview(nextOverview)
      setJob(nextJob)
      setSettings(nextSettings)
      setError(null)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '无法读取语义分析状态')
    }
  }, [])

  useEffect(() => { void load() }, [load])

  useEffect(() => {
    const refresh = () => void load()
    window.addEventListener('firmatlas:semantic-analysis-updated', refresh)
    return () => window.removeEventListener('firmatlas:semantic-analysis-updated', refresh)
  }, [load])

  useEffect(() => {
    if (job?.status !== 'running') return
    const timer = window.setInterval(() => {
      void Promise.all([
        intelligenceApi.semanticLatestJob(), intelligenceApi.semanticOverview(),
      ]).then(([nextJob, nextOverview]) => {
        setJob(nextJob)
        setOverview(nextOverview)
      }).catch(() => undefined)
    }, 1200)
    return () => window.clearInterval(timer)
  }, [job?.status])

  const start = async () => {
    setStarting(true)
    setError(null)
    try {
      await intelligenceApi.startSemanticJob(false)
      window.setTimeout(() => void load(), 180)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '无法启动分析')
    } finally {
      setStarting(false)
    }
  }

  const running = starting || job?.status === 'running'
  const coverage = overview?.total ? (overview.analyzed / overview.total) * 100 : 0
  const jobProgress = job?.total_count ? (job.processed_count / job.total_count) * 100 : 0

  return (
    <div>
      <header className="mb-7 flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="eyebrow"><BrainCircuit size={13} /> Secondary intelligence / Evidence extraction</div>
          <h1 className="mt-3 text-[30px] font-semibold leading-none tracking-[-0.045em] text-white sm:text-[38px]">接口与参数语义分析</h1>
          <p className="mt-3 max-w-3xl text-xs leading-6 text-slate-500 sm:text-sm">从固件漏洞描述中提取通信接口、参数、请求方式与安全影响；全库增量检查默认零 Token，单条详情可按模型配置增强。</p>
        </div>
        <div className="flex gap-2">
          <button type="button" onClick={onConfigureModel} className="filter-button h-11"><KeyRound size={15} /> 模型配置</button>
          <button type="button" onClick={() => void start()} disabled={running} className="flex h-11 items-center gap-2 rounded-xl bg-signal px-4 text-xs font-semibold text-[#11170a] shadow-signal transition hover:-translate-y-0.5 disabled:cursor-wait disabled:opacity-60">
            {running ? <LoaderCircle size={15} className="animate-spin" /> : <Play size={15} />}
            {running ? '分析运行中' : overview?.pending ? '分析未处理记录' : '检查新增记录'}
          </button>
        </div>
      </header>

      <nav aria-label="语义洞察视图" className="mb-4 flex gap-1 overflow-x-auto rounded-2xl border border-white/[0.07] bg-white/[0.025] p-1.5">
        {([
          ['overview', '分析概览', LayoutDashboard],
          ['interface', '接口明细', ListTree],
          ['parameter', '参数明细', Braces],
          ['category', '智能关联', Waypoints],
        ] as const).map(([value, label, Icon]) => (
          <button key={value} type="button" onClick={() => setSection(value)} aria-pressed={section === value} className={`flex h-9 shrink-0 items-center gap-2 rounded-xl px-3.5 text-[11px] font-medium transition ${section === value ? 'bg-white/[0.085] text-white shadow-inner shadow-white/[0.04]' : 'text-slate-600 hover:bg-white/[0.035] hover:text-slate-300'}`}>
            <Icon size={14} className={section === value ? 'text-signal' : ''} />{label}
          </button>
        ))}
      </nav>

      {error && <div role="alert" className="mb-4 rounded-xl border border-ember/20 bg-ember/[0.06] px-4 py-3 text-xs text-ember">{error}</div>}

      {section === 'overview' ? <>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard icon={DatabaseZap} label="覆盖漏洞" value={`${formatCompactNumber(overview?.analyzed ?? 0)} / ${formatCompactNumber(overview?.total ?? 0)}`} note={`${coverage.toFixed(1)}% 已建立分析记录`} tone="signal" />
        <MetricCard icon={Route} label="通信接口" value={formatCompactNumber(overview?.interfaces ?? 0)} note="Web 路由、RPC、消息与命令入口" tone="cyan" />
        <MetricCard icon={Braces} label="接口参数" value={formatCompactNumber(overview?.parameters ?? 0)} note="保留所属接口与安全影响" tone="violet" />
        <MetricCard icon={Sparkles} label="模型 Token" value={formatCompactNumber((overview?.prompt_tokens ?? 0) + (overview?.completion_tokens ?? 0))} note={settings?.active ? `${settings.model} · 已启用` : '当前为零 Token 规则模式'} tone="ember" />
      </div>

      <section className="mt-4 overflow-hidden rounded-[22px] border border-white/[0.08] bg-[#0e141d]/85 p-5 shadow-lift sm:p-6">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-4">
            <div className={`grid h-12 w-12 place-items-center rounded-2xl border ${running ? 'border-signal/25 bg-signal/[0.08] text-signal' : 'border-white/[0.08] bg-white/[0.03] text-slate-500'}`}>
              {running ? <Activity size={20} className="animate-pulse" /> : job?.status === 'succeeded' ? <CheckCircle2 size={20} /> : <CircleDotDashed size={20} />}
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white">{running ? '全库分析正在运行' : job ? '最近一次分析运行' : '尚未执行全库分析'}</h2>
              <p className="mt-1 text-[11px] text-slate-600">{job ? `${job.strategy === 'hybrid' ? '规则 + 本地模型' : '确定性规则'} · ${formatRelativeTime(job.finished_at || job.started_at)}` : '首次运行会遍历所有固件相关漏洞描述'}</p>
            </div>
          </div>
          <div className="grid grid-cols-4 gap-5 text-center text-[10px] lg:min-w-[440px]">
            <RunStat label="已处理" value={job?.processed_count ?? 0} />
            <RunStat label="新分析" value={job?.analyzed_count ?? 0} />
            <RunStat label="缓存命中" value={job?.cached_count ?? 0} />
            <RunStat label="失败" value={job?.failed_count ?? 0} danger />
          </div>
        </div>
        <div className="mt-5 h-1.5 overflow-hidden rounded-full bg-white/[0.05]">
          <div className={`h-full rounded-full bg-gradient-to-r from-cyan to-signal transition-[width] duration-500 ${running ? 'shadow-signal' : ''}`} style={{ width: `${jobProgress}%` }} />
        </div>
        <div className="mt-2 flex justify-between font-mono text-[9px] text-slate-700"><span>{jobProgress.toFixed(1)}%</span><span>{job?.processed_count ?? 0} / {job?.total_count ?? overview?.total ?? 0}</span></div>
      </section>

      <div className="mt-4 grid gap-4 xl:grid-cols-[1.05fr_.95fr]">
        <ObservationList title="高频通信接口" eyebrow="Interface atlas" icon={Cable} items={overview?.top_interfaces ?? []} empty="运行分析后显示接口分布" />
        <ObservationList title="高频输入参数" eyebrow="Parameter surface" icon={Braces} items={overview?.top_parameters ?? []} empty="运行分析后显示参数分布" />
      </div>

      <section className="mt-4 rounded-[22px] border border-white/[0.07] bg-white/[0.025] p-5 sm:p-6">
        <div className="eyebrow"><ScanSearch size={13} /> Analysis pipeline</div>
        <div className="mt-5 grid gap-3 lg:grid-cols-[1fr_auto_1fr_auto_1fr] lg:items-center">
          <PipelineStep icon={ScanSearch} index="01" title="规则提取" text="路径、CGI、HTTP 方法、参数与攻击语义；零 Token。" />
          <ArrowRight className="hidden text-slate-800 lg:block" size={18} />
          <PipelineStep icon={BrainCircuit} index="02" title="模型增强" text="单条分析可调用 48760 兼容模型；全库调用必须由 API 显式授权。" />
          <ArrowRight className="hidden text-slate-800 lg:block" size={18} />
          <PipelineStep icon={DatabaseZap} index="03" title="指纹归档" text="内容、分析器与模型配置共同生成指纹，缓存命中不重复调用。" />
        </div>
      </section>
      </> : <SemanticExplorer mode={section} />}
    </div>
  )
}

function MetricCard({ icon: Icon, label, value, note, tone }: { icon: typeof Route; label: string; value: string; note: string; tone: string }) {
  return <article className="rounded-2xl border border-white/[0.07] bg-white/[0.035] p-5"><div className="flex items-center justify-between"><span className="text-xs text-slate-500">{label}</span><span className={`tone-${tone} rounded-lg p-1.5`}><Icon size={15} /></span></div><strong className="mt-4 block text-2xl tracking-[-0.04em] text-white">{value}</strong><p className="mt-1.5 text-[10px] text-slate-700">{note}</p></article>
}

function RunStat({ label, value, danger = false }: { label: string; value: number; danger?: boolean }) {
  return <div><strong className={`block font-mono text-sm ${danger && value ? 'text-ember' : 'text-slate-300'}`}>{value}</strong><span className="mt-1 block text-slate-700">{label}</span></div>
}

function ObservationList({ title, eyebrow, icon: Icon, items, empty }: { title: string; eyebrow: string; icon: typeof Cable; items: Array<{ label: string; value: number }>; empty: string }) {
  const max = Math.max(...items.map((item) => item.value), 1)
  return <section className="rounded-[22px] border border-white/[0.07] bg-[#0e141d]/70 p-5 sm:p-6"><div className="eyebrow"><Icon size={13} /> {eyebrow}</div><h2 className="mt-2 text-lg font-semibold text-white">{title}</h2><div className="mt-5 space-y-3">{items.map((item) => <div key={item.label} className="grid grid-cols-[minmax(0,180px)_1fr_44px] items-center gap-3"><code className="truncate text-[10px] text-slate-400" title={item.label}>{item.label}</code><span className="h-1 overflow-hidden rounded-full bg-white/[0.06]"><span className="block h-full rounded-full bg-gradient-to-r from-cyan/40 to-signal" style={{ width: `${Math.max(5, item.value / max * 100)}%` }} /></span><span className="text-right font-mono text-[10px] text-slate-600">{item.value}</span></div>)}{!items.length && <p className="py-10 text-center text-xs text-slate-700">{empty}</p>}</div></section>
}

function PipelineStep({ icon: Icon, index, title, text }: { icon: typeof Clock3; index: string; title: string; text: string }) {
  return <div className="flex gap-3 rounded-2xl border border-white/[0.06] bg-black/10 p-4"><div className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-white/[0.04] text-signal"><Icon size={16} /></div><div><div className="font-mono text-[8px] text-slate-700">{index}</div><div className="mt-0.5 text-xs font-medium text-slate-300">{title}</div><p className="mt-1 text-[10px] leading-5 text-slate-600">{text}</p></div></div>
}
