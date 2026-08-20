import {
  Activity, Binary, Braces, CheckCircle2, ChevronRight, CircleDot, Database, EyeOff,
  FileArchive, FileCode2, GitCompareArrows, LoaderCircle, Minus, Plus, Radar,
  Search, ShieldCheck, ShieldQuestion, Sparkles, TriangleAlert, UploadCloud, Waypoints,
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { intelligenceApi } from '../api/client'
import { useDebouncedValue } from '../hooks/useDebouncedValue'
import type {
  FirmwareMappingJob, MappingCandidate, MappingCandidateDetail, MappingCatalogSummary,
  MappingCorpusReport,
  MappingReasoningCapability, MappingReasoningRun,
  MappingSnapshotChange, MappingSnapshotDiff, PotentialHiddenInterface,
  PotentialHiddenInterfacePage,
} from '../types'
import { CommunicationGraphWorkspace } from './CommunicationGraphWorkspace'

const kinds = [
  ['', '全部能力'], ['request_interface', '请求接口'], ['web_configuration', 'Web 配置'],
  ['script_route', '脚本路由'], ['native_hint', '原生提示'],
  ['native_route_binding', 'Native 绑定'], ['native_handler', 'Native Handler'],
  ['native_parameter_state_flow', '参数状态流'],
  ['native_configuration_url_ipc_flow', 'URL IPC'],
  ['native_configuration_url_consumer', 'URL 状态消费者'],
  ['native_cgi_selector', 'CGI 组合路由'],
  ['runtime_principal', '运行时主体'],
  ['ubus_backend_binding', 'ubus 后端绑定'],
  ['ubus_access_grant', 'ubus 访问策略'],
  ['set_difference_attribution', '集合差异'],
  ['candidate_association', '跨层关联'],
] as const

export function MappingCatalogWorkspace() {
  const [catalogs, setCatalogs] = useState<MappingCatalogSummary[]>([])
  const [catalogId, setCatalogId] = useState('')
  const [candidates, setCandidates] = useState<MappingCandidate[]>([])
  const [selected, setSelected] = useState<MappingCandidateDetail | null>(null)
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [view, setView] = useState<'catalog' | 'graph' | 'hidden' | 'compare' | 'upload' | 'corpus'>('catalog')
  const [corpusReport, setCorpusReport] = useState<MappingCorpusReport | null>(null)
  const [hiddenQuery, setHiddenQuery] = useState('')
  const [hiddenPage, setHiddenPage] = useState<PotentialHiddenInterfacePage | null>(null)
  const [selectedHidden, setSelectedHidden] = useState<PotentialHiddenInterface | null>(null)
  const [baseCatalogId, setBaseCatalogId] = useState('')
  const [targetCatalogId, setTargetCatalogId] = useState('')
  const [snapshotDiff, setSnapshotDiff] = useState<MappingSnapshotDiff | null>(null)
  const [selectedChange, setSelectedChange] = useState<MappingSnapshotChange | null>(null)
  const debouncedQuery = useDebouncedValue(query, 180)
  const debouncedHiddenQuery = useDebouncedValue(hiddenQuery, 180)

  useEffect(() => {
    if (view !== 'corpus') return
    const controller = new AbortController()
    setLoading(true)
    void intelligenceApi.mappingCorpusReport(controller.signal).then((report) => {
      setCorpusReport(report)
      setError(null)
    }).catch((caught) => {
      if (!controller.signal.aborted) {
        setError(caught instanceof Error ? caught.message : '代表性语料报告加载失败')
      }
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [view])

  useEffect(() => {
    const controller = new AbortController()
    void intelligenceApi.mappingCatalogs(controller.signal).then((page) => {
      setCatalogs(page.items)
      setCatalogId((current) => current || page.items[0]?.catalog_id || '')
      if (page.items.length >= 2) {
        setBaseCatalogId((current) => current || page.items[1].catalog_id)
        setTargetCatalogId((current) => current || page.items[0].catalog_id)
      }
      setError(null)
    }).catch((caught) => {
      if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : '目录加载失败')
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    if (!catalogId) { setCandidates([]); return }
    const controller = new AbortController()
    setLoading(true)
    void intelligenceApi.mappingCandidates(
      catalogId, { query: debouncedQuery, kind }, controller.signal,
    ).then((page) => {
      setCandidates(page.items)
      setSelected((current) => page.items.some((x) => x.candidate_id === current?.candidate.candidate_id)
        ? current : null)
      setError(null)
    }).catch((caught) => {
      if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : '能力查询失败')
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [catalogId, debouncedQuery, kind])

  useEffect(() => {
    if (view !== 'hidden') return
    const controller = new AbortController()
    setLoading(true)
    void intelligenceApi.potentialHiddenInterfaces(
      debouncedHiddenQuery, controller.signal,
    ).then((page) => {
      setHiddenPage(page)
      setSelectedHidden((current) => page.items.some(
        (item) => item.interface_id === current?.interface_id,
      ) ? current : null)
      setError(null)
    }).catch((caught) => {
      if (!controller.signal.aborted) {
        setError(caught instanceof Error ? caught.message : '潜在隐藏接口加载失败')
      }
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [view, debouncedHiddenQuery])

  useEffect(() => {
    if (view !== 'compare') return
    if (!baseCatalogId || !targetCatalogId || baseCatalogId === targetCatalogId) {
      setSnapshotDiff(null)
      setSelectedChange(null)
      return
    }
    const controller = new AbortController()
    setLoading(true)
    void intelligenceApi.compareMappingCatalogs(
      baseCatalogId, targetCatalogId, controller.signal,
    ).then((result) => {
      setSnapshotDiff(result)
      setSelectedChange((current) => result.changes.some(
        (item) => item.change_id === current?.change_id,
      ) ? current : null)
      setError(null)
    }).catch((caught) => {
      if (!controller.signal.aborted) {
        setError(caught instanceof Error ? caught.message : '版本测绘差异加载失败')
      }
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [view, baseCatalogId, targetCatalogId])

  const activeCatalog = useMemo(
    () => catalogs.find((item) => item.catalog_id === catalogId), [catalogId, catalogs],
  )

  const openCandidate = async (candidate: MappingCandidate) => {
    try {
      setSelected(await intelligenceApi.mappingCandidate(catalogId, candidate.candidate_id))
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '证据详情加载失败')
    }
  }

  const refreshPublishedCatalogs = useCallback(async (job: FirmwareMappingJob) => {
    const page = await intelligenceApi.mappingCatalogs()
    setCatalogs(page.items)
    setCatalogId(job.catalog_id || page.items[0]?.catalog_id || '')
  }, [])

  return (
    <section>
      {/* Design rationale: a stable three-column evidence hierarchy replaces overlapping drawers;
          restrained glass surfaces preserve FirmAtlas density while responsive stacking keeps it legible. */}
      <header className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="eyebrow"><Waypoints size={13} /> Firmware mapping / Discovery catalog</div>
          <h1 className="mt-3 text-[30px] font-semibold tracking-[-0.045em] text-white sm:text-[38px]">通信测绘目录</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">从前端请求、Web 配置、脚本后端与原生提示中发布可追溯候选，保留覆盖状态与未决分析义务。</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex rounded-xl border border-white/[0.07] bg-black/20 p-1">
            <button type="button" onClick={() => setView('catalog')} className={`rounded-lg px-3 py-2 text-[10px] transition ${view === 'catalog' ? 'bg-white/[0.08] text-white' : 'text-slate-600 hover:text-slate-300'}`}>目录浏览</button>
            <button type="button" onClick={() => setView('graph')} className={`rounded-lg px-3 py-2 text-[10px] transition ${view === 'graph' ? 'bg-cyan/[0.1] text-cyan' : 'text-slate-600 hover:text-slate-300'}`}>架构图谱</button>
            <button type="button" onClick={() => setView('hidden')} className={`rounded-lg px-3 py-2 text-[10px] transition ${view === 'hidden' ? 'bg-signal/[0.1] text-signal' : 'text-slate-600 hover:text-slate-300'}`}>潜在隐藏接口</button>
            <button type="button" onClick={() => setView('compare')} className={`rounded-lg px-3 py-2 text-[10px] transition ${view === 'compare' ? 'bg-cyan/[0.1] text-cyan' : 'text-slate-600 hover:text-slate-300'}`}>版本对比</button>
            <button type="button" onClick={() => setView('corpus')} className={`rounded-lg px-3 py-2 text-[10px] transition ${view === 'corpus' ? 'bg-signal/[0.1] text-signal' : 'text-slate-600 hover:text-slate-300'}`}>语料门禁</button>
            <button type="button" onClick={() => setView('upload')} className={`rounded-lg px-3 py-2 text-[10px] transition ${view === 'upload' ? 'bg-signal/[0.1] text-signal' : 'text-slate-600 hover:text-slate-300'}`}>上传分析</button>
          </div>
          {view === 'catalog' && activeCatalog && <StatusPill catalog={activeCatalog} />}
        </div>
      </header>

      {error && <div role="alert" className="mb-4 rounded-xl border border-ember/20 bg-ember/[0.06] px-4 py-3 text-xs text-ember">{error}</div>}

      {view === 'corpus' ? <CorpusGateWorkspace report={corpusReport} loading={loading} /> : view === 'upload' ? <FirmwareUploadWorkspace
        onPublished={refreshPublishedCatalogs} onOpenGraph={() => setView('graph')}
      /> : view === 'graph' ? <CommunicationGraphWorkspace /> : view === 'hidden' ? <HiddenInterfaceWorkspace
        page={hiddenPage} query={hiddenQuery} onQuery={setHiddenQuery}
        selected={selectedHidden} onSelect={setSelectedHidden} loading={loading}
      /> : view === 'compare' ? <SnapshotComparisonWorkspace
        catalogs={catalogs} baseCatalogId={baseCatalogId} targetCatalogId={targetCatalogId}
        onBaseCatalog={setBaseCatalogId} onTargetCatalog={setTargetCatalogId}
        result={snapshotDiff} selected={selectedChange} onSelect={setSelectedChange}
        loading={loading}
      /> : !loading && catalogs.length === 0 ? <EmptyCatalog /> : (
        <div className="grid min-h-[640px] overflow-hidden rounded-2xl border border-white/[0.07] bg-[#0a0f17]/75 backdrop-blur-xl xl:grid-cols-[260px_minmax(360px,0.9fr)_minmax(420px,1.1fr)]">
          <aside className="border-b border-white/[0.07] p-4 xl:border-b-0 xl:border-r">
            <div className="eyebrow"><Database size={12} /> Catalog versions</div>
            <div className="mt-4 space-y-2">
              {catalogs.map((catalog) => (
                <button key={catalog.catalog_id} type="button" onClick={() => { setCatalogId(catalog.catalog_id); setSelected(null) }}
                  aria-label={`选择目录 ${catalog.firmware_artifact_sha256.slice(0, 12)}`}
                  className={`w-full rounded-xl border p-3 text-left transition ${catalogId === catalog.catalog_id ? 'border-signal/25 bg-signal/[0.07]' : 'border-white/[0.06] bg-white/[0.02] hover:bg-white/[0.045]'}`}>
                  <div className="flex items-center justify-between text-[10px] uppercase tracking-[0.12em] text-slate-600"><span>Firmware</span><span>{catalog.coverage_status}</span></div>
                  <div className="mt-2 font-mono text-xs text-slate-200">{catalog.firmware_artifact_sha256.slice(0, 16)}…</div>
                  <div className="mt-2 text-[9px] uppercase tracking-[0.1em] text-slate-600">Inventory {catalog.source_inventory_coverage_status}</div>
                  <div className="mt-3 flex gap-3 text-[10px] text-slate-500"><span>{catalog.candidate_count} 候选</span><span>{catalog.association_count} 关联</span><span>{catalog.open_obligation_count} 未决</span></div>
                </button>
              ))}
            </div>
          </aside>

          <div className="border-b border-white/[0.07] xl:border-b-0 xl:border-r">
            <div className="border-b border-white/[0.07] p-4">
              <label className="search-field"><Search size={15} /><input aria-label="搜索测绘候选" placeholder="搜索接口、路径、构造或属性…" value={query} onChange={(event) => setQuery(event.target.value)} /></label>
              <div className="mt-3 flex gap-2 overflow-x-auto pb-1">{kinds.map(([value, label]) => <button key={value} type="button" onClick={() => setKind(value)} className={`shrink-0 rounded-lg border px-2.5 py-1.5 text-[10px] transition ${kind === value ? 'border-cyan/25 bg-cyan/[0.08] text-cyan' : 'border-white/[0.06] text-slate-600 hover:text-slate-300'}`}>{label}</button>)}</div>
            </div>
            <div className="max-h-[550px] overflow-y-auto p-2">
              {loading && <div className="p-8 text-center text-xs text-slate-600">正在读取目录投影…</div>}
              {!loading && candidates.length === 0 && <div className="p-8 text-center text-xs text-slate-600">没有符合当前条件的候选</div>}
              {candidates.map((candidate) => <CandidateRow key={candidate.candidate_id} candidate={candidate} active={selected?.candidate.candidate_id === candidate.candidate_id} onClick={() => void openCandidate(candidate)} />)}
            </div>
          </div>

          <div className="min-w-0 bg-gradient-to-br from-white/[0.025] to-transparent">
            {selected ? <CandidateEvidence detail={selected} /> : <div className="grid h-full min-h-[420px] place-items-center p-8 text-center"><div><CircleDot className="mx-auto text-signal/40" size={34} /><h2 className="mt-4 text-sm font-medium text-slate-300">选择一个通信候选</h2><p className="mt-2 text-xs leading-5 text-slate-600">查看参数、跨层关联、证据位置与尚未完成的分析义务。</p></div></div>}
          </div>
        </div>
      )}
    </section>
  )
}

const corpusCategoryLabels: Record<string, string> = {
  form_handler: '表单处理链',
  hnap_soap: 'HNAP / SOAP',
  cgi_gateway: '共享 CGI 网关',
  frontend: '前端请求',
  web_configuration: 'Web 配置',
  script_backend: '脚本后端',
  native_only: '纯原生注册',
  hybrid: '混合链路',
}

const corpusStatusLabels: Record<string, string> = {
  verified: '已验证', derived_only: '仅派生验证', contract_only: '仅契约验证',
  coverage_gap: '覆盖缺口', acquisition_gap: '样本获取缺口',
}

const corpusRoleLabels: Record<string, string> = {
  positive: '正向样本',
  regression: '回归样本',
  'independent-holdout': '独立 holdout',
}

function CorpusGateWorkspace({
  report, loading,
}: {
  report: MappingCorpusReport | null
  loading: boolean
}) {
  if (loading && !report) {
    return <div className="grid min-h-[480px] place-items-center rounded-2xl border border-white/[0.07] bg-[#0a0f17]/75 text-xs text-slate-600">正在核对代表性通信架构…</div>
  }
  if (!report) {
    return <div className="grid min-h-[480px] place-items-center rounded-2xl border border-white/[0.07] bg-[#0a0f17]/75 text-xs text-slate-600">尚未发布代表性语料门禁报告</div>
  }
  const passed = report.gate_status === 'passed'
  return <div className="detail-enter space-y-4">
    <div className={`overflow-hidden rounded-2xl border p-6 ${passed ? 'border-signal/20 bg-gradient-to-br from-signal/[0.09] via-[#0a1118] to-[#090d13]' : 'border-ember/20 bg-ember/[0.04]'}`}>
      <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className={`eyebrow ${passed ? 'text-signal' : 'text-ember'}`}><ShieldCheck size={13} /> Representative corpus / {report.corpus_version}</div>
          <h2 className="mt-3 text-2xl font-semibold tracking-[-0.035em] text-white">{passed ? '五类通信架构门禁通过' : '通信架构门禁尚未通过'}</h2>
          <p className="mt-2 max-w-3xl text-xs leading-6 text-slate-500">门禁按真实固件证据和候选范围验收表单处理、HNAP/SOAP、共享 CGI、脚本后端与纯原生注册；禁止把另一架构的证据借给当前样本。</p>
        </div>
        <div className="rounded-2xl border border-white/[0.08] bg-black/20 px-6 py-4 text-center">
          <div className={`font-mono text-3xl font-semibold ${passed ? 'text-signal' : 'text-ember'}`}>{report.categories.filter((item) => item.status === 'verified').length}/{report.required_categories.length}</div>
          <div className="mt-1 text-[9px] uppercase tracking-[0.16em] text-slate-600">required categories verified</div>
        </div>
      </div>
    </div>

    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
      {report.categories.filter((item) => report.required_categories.includes(item.architecture_category)).map((category) => <div key={category.architecture_category} className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-4">
        <div className="flex items-start justify-between gap-2"><div className="text-xs font-medium text-slate-200">{corpusCategoryLabels[category.architecture_category] ?? category.architecture_category}</div><span className={`rounded-full border px-2 py-1 text-[9px] ${category.status === 'verified' ? 'border-signal/20 bg-signal/[0.07] text-signal' : 'border-ember/20 bg-ember/[0.07] text-ember'}`}>{corpusStatusLabels[category.status]}</span></div>
        <div className="mt-4 flex gap-4 font-mono text-[10px] text-slate-500"><span>{category.real_firmware_verified_count} real</span><span>{category.coverage_gap_count} gap</span></div>
        <div className="mt-3 text-[9px] leading-4 text-slate-600">{category.candidate_kinds.join(' · ') || 'no candidate kind'}</div>
      </div>)}
    </div>

    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(320px,0.8fr)]">
      <div className="rounded-2xl border border-white/[0.07] bg-[#0a0f17]/75 p-5">
        <div className="eyebrow"><Radar size={12} /> Scope-aware evidence samples</div>
        <div className="mt-4 space-y-3">{report.samples.filter((sample) => sample.status === 'verified').map((sample) => <div key={sample.sample_id} className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between"><div><div className="flex flex-wrap items-center gap-2"><div className="font-mono text-xs text-slate-200">{sample.sample_id}</div><span className="rounded-full border border-cyan/15 bg-cyan/[0.05] px-2 py-0.5 text-[9px] text-cyan">{corpusRoleLabels[sample.role] ?? sample.role}</span></div><div className="mt-1 text-[10px] text-slate-600">{corpusCategoryLabels[sample.architecture_category] ?? sample.architecture_category} · {sample.architecture_subtype}</div></div><span className="text-[10px] text-signal">{sample.candidate_count} 候选 · {sample.evidence_count} 证据</span></div>
          <div className="mt-3 flex flex-wrap gap-1.5">{sample.observed_capabilities.map((capability) => <span key={capability} className="rounded-md border border-white/[0.06] bg-black/20 px-2 py-1 font-mono text-[9px] text-slate-500">{capability}</span>)}</div>
          <div className="mt-3 text-[9px] text-slate-600">范围约束 {sample.scope_candidate_ids.length ? `${sample.scope_candidate_ids.length} 个候选` : '整个 Catalog'} · 未决义务 {sample.open_obligation_count}</div>
        </div>)}</div>
      </div>
      <aside className="rounded-2xl border border-cyan/15 bg-cyan/[0.035] p-5">
        <div className="eyebrow text-cyan"><ShieldQuestion size={12} /> Interpretation boundary</div>
        <h3 className="mt-4 text-sm font-medium text-slate-200">通过代表类别，不夸大泛化范围</h3>
        <p className="mt-3 text-xs leading-6 text-slate-500">门禁通过不等于所有厂商与子类型均已泛化验证。FRITZ!Box 4040 已作为独立 holdout 发布 24 个原生 UBUS 方法；D-Link DAP-2695 也已从原始固件完成 485 个 PHP 源文件的脚本后端作用域 Catalog，同时保留整固件分析中的独立 partial 诊断。</p>
        <div className="mt-5 rounded-xl border border-white/[0.06] bg-black/20 p-3 font-mono text-[9px] leading-5 text-slate-600">report {report.report_id.slice(0, 30)}…<br />schema {report.schema_version}<br />capability policy {report.capability_policy_version}</div>
      </aside>
    </div>
  </div>
}

function FirmwareUploadWorkspace({
  onPublished, onOpenGraph,
}: {
  onPublished: (job: FirmwareMappingJob) => Promise<void>
  onOpenGraph: () => void
}) {
  const [enabled, setEnabled] = useState<boolean | null>(null)
  const [maxBytes, setMaxBytes] = useState(0)
  const [file, setFile] = useState<File | null>(null)
  const [job, setJob] = useState<FirmwareMappingJob | null>(null)
  const [recent, setRecent] = useState<FirmwareMappingJob[]>([])
  const [submitting, setSubmitting] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [reasoningCapability, setReasoningCapability] = useState<MappingReasoningCapability | null>(null)
  const [reasoningRun, setReasoningRun] = useState<MappingReasoningRun | null>(null)
  const [reasoningBusy, setReasoningBusy] = useState(false)

  useEffect(() => {
    const controller = new AbortController()
    void intelligenceApi.mappingJobs(controller.signal).then((page) => {
      setEnabled(page.enabled)
      setMaxBytes(page.max_upload_bytes)
      setRecent(page.items)
      setJob(page.items[0] ?? null)
    }).catch((caught) => {
      if (!controller.signal.aborted) setMessage(caught instanceof Error ? caught.message : '分析任务加载失败')
    })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    if (!job || !['queued', 'running'].includes(job.status)) return
    const controller = new AbortController()
    const timer = window.setTimeout(() => {
      void intelligenceApi.mappingJob(job.job_id, controller.signal).then(async (next) => {
        setJob(next)
        setRecent((items) => [next, ...items.filter((item) => item.job_id !== next.job_id)])
        if (next.status === 'completed' || next.status === 'partial') await onPublished(next)
      }).catch((caught) => {
        if (!controller.signal.aborted) setMessage(caught instanceof Error ? caught.message : '分析状态更新失败')
      })
    }, 1000)
    return () => { controller.abort(); window.clearTimeout(timer) }
  }, [job, onPublished])

  useEffect(() => {
    if (!job?.catalog_id) { setReasoningCapability(null); setReasoningRun(null); return }
    const controller = new AbortController()
    void intelligenceApi.mappingReasoning(job.catalog_id, controller.signal).then((capability) => {
      setReasoningCapability(capability)
      setReasoningRun(capability.latest)
    }).catch((caught) => {
      if (!controller.signal.aborted) setMessage(caught instanceof Error ? caught.message : '模型能力加载失败')
    })
    return () => controller.abort()
  }, [job?.catalog_id])

  useEffect(() => {
    if (!job?.catalog_id || !reasoningRun || !['queued', 'running'].includes(reasoningRun.status)) return
    const controller = new AbortController()
    const timer = window.setTimeout(() => {
      void intelligenceApi.mappingReasoning(job.catalog_id!, controller.signal).then((capability) => {
        setReasoningCapability(capability)
        setReasoningRun(capability.latest)
      }).catch((caught) => {
        if (!controller.signal.aborted) setMessage(caught instanceof Error ? caught.message : '模型状态更新失败')
      })
    }, 1000)
    return () => { controller.abort(); window.clearTimeout(timer) }
  }, [job?.catalog_id, reasoningRun])

  const submit = async () => {
    if (!file) return
    if (file.size <= 0) { setMessage('固件制品不能为空'); return }
    if (maxBytes && file.size > maxBytes) { setMessage('固件制品超过服务端上传预算'); return }
    setSubmitting(true)
    setMessage(null)
    try {
      const next = await intelligenceApi.submitFirmwareMappingJob(file)
      setJob(next)
      setRecent((items) => [next, ...items.filter((item) => item.job_id !== next.job_id)])
      if (next.status === 'completed' || next.status === 'partial') await onPublished(next)
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : '固件提交失败')
    } finally {
      setSubmitting(false)
    }
  }

  const submitReasoning = async () => {
    if (!job?.catalog_id) return
    setReasoningBusy(true)
    setMessage(null)
    try {
      setReasoningRun(await intelligenceApi.submitMappingReasoning(job.catalog_id))
    } catch (caught) {
      setMessage(caught instanceof Error ? caught.message : 'MiniMax 线索补充失败')
    } finally {
      setReasoningBusy(false)
    }
  }

  const active = job?.status === 'queued' || job?.status === 'running'
  const statusLabel = job?.status === 'completed' ? '分析已完成'
    : job?.status === 'partial' ? '分析部分完成'
      : job?.status === 'failed' ? '分析失败'
        : job?.status === 'running' ? '正在恢复通信结构' : job ? '等待分析资源' : '尚未提交固件'

  return <div className="detail-enter grid gap-4 xl:grid-cols-[minmax(420px,1.15fr)_minmax(320px,0.85fr)]">
    {/* Design rationale: upload intent, safety budget, and immutable result identity share one
        responsive glass surface; lifecycle evidence stays visible instead of disappearing into a modal. */}
    <section className="overflow-hidden rounded-2xl border border-white/[0.07] bg-[radial-gradient(circle_at_12%_0%,rgba(73,214,179,0.08),transparent_38%),rgba(10,15,23,0.82)] p-6 backdrop-blur-xl">
      <div className="flex items-start gap-4"><div className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl border border-signal/20 bg-signal/[0.07] text-signal"><UploadCloud size={22} /></div><div><div className="eyebrow">Raw artifact / Isolated AnalyzeRun</div><h2 className="mt-2 text-xl font-semibold text-white">上传一个固件制品</h2><p className="mt-2 max-w-xl text-xs leading-6 text-slate-500">文件按 SHA-256 内容寻址保存，在无网络、只读根容器中解包。HTTP 请求只创建异步任务，不直接执行分析器。</p></div></div>
      <label className="mt-7 block rounded-2xl border border-dashed border-white/[0.12] bg-black/20 p-5 transition focus-within:border-signal/30 hover:border-white/[0.2]"><span className="flex items-center gap-2 text-xs text-slate-300"><FileArchive size={16} className="text-signal" /> 选择固件制品</span><input aria-label="选择固件制品" type="file" className="mt-4 block w-full text-[11px] text-slate-500 file:mr-4 file:rounded-lg file:border-0 file:bg-white/[0.07] file:px-3 file:py-2 file:text-[10px] file:text-slate-300 hover:file:bg-white/[0.1]" onChange={(event) => { setFile(event.target.files?.[0] ?? null); setMessage(null) }} /></label>
      <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"><div className="text-[10px] leading-5 text-slate-600">{enabled === false ? '当前服务未配置固定 Binwalk 运行时' : enabled === null ? '正在读取服务能力…' : `单文件上限 ${formatBytes(maxBytes)} · 单任务串行执行`}</div><button type="button" onClick={() => void submit()} disabled={!enabled || !file || submitting || active} className="inline-flex items-center justify-center gap-2 rounded-xl border border-signal/20 bg-signal/[0.09] px-4 py-2.5 text-xs font-medium text-signal transition hover:bg-signal/[0.14] disabled:cursor-not-allowed disabled:opacity-35">{submitting || active ? <LoaderCircle size={15} className="animate-spin" /> : <UploadCloud size={15} />}开始独立分析</button></div>
      {message && <div role="alert" className="mt-4 rounded-xl border border-ember/20 bg-ember/[0.05] px-4 py-3 text-xs text-ember">{message}</div>}
    </section>

    <section className="rounded-2xl border border-white/[0.07] bg-[#0a0f17]/80 p-5 backdrop-blur-xl"><div className="flex items-center justify-between"><div><div className="eyebrow">Analysis lifecycle</div><h3 className="mt-2 text-sm font-medium text-slate-200">{statusLabel}</h3></div>{job && (job.status === 'completed' || job.status === 'partial') ? <CheckCircle2 size={22} className="text-signal" /> : active ? <LoaderCircle size={22} className="animate-spin text-cyan" /> : <Activity size={22} className="text-slate-700" />}</div>{job ? <div className="mt-5 space-y-3"><JobDatum label="制品" value={job.original_filename} /><JobDatum label="SHA-256" value={`${job.firmware_artifact_sha256.slice(0, 16)}…`} mono /><JobDatum label="状态" value={job.status} /><JobDatum label="Catalog" value={job.catalog_id || '等待发布'} mono /><JobDatum label="Graph" value={job.graph_id || '等待发布'} mono />{active && <div className="h-1 overflow-hidden rounded-full bg-white/[0.05]"><div className="h-full w-2/3 animate-pulse rounded-full bg-gradient-to-r from-cyan/30 to-signal/70" /></div>}{job.graph_id && <button type="button" onClick={onOpenGraph} className="mt-2 w-full rounded-xl border border-cyan/15 bg-cyan/[0.05] px-3 py-2.5 text-xs text-cyan transition hover:bg-cyan/[0.09]">查看生成图谱</button>}</div> : <p className="mt-6 text-xs leading-6 text-slate-600">提交后这里会持续显示排队、执行、部分完成或失败状态，并保留 Catalog 与 Graph 身份。</p>}<div className="mt-6 border-t border-white/[0.06] pt-4"><div className="text-[9px] uppercase tracking-[0.12em] text-slate-700">最近任务 {recent.length}</div></div></section>

    {job?.catalog_id && <section className="xl:col-span-2 overflow-hidden rounded-2xl border border-violet-400/15 bg-[radial-gradient(circle_at_88%_0%,rgba(167,139,250,0.09),transparent_34%),rgba(10,15,23,0.84)] p-6 backdrop-blur-xl">
      {/* Design rationale: the model surface uses a distinct violet trust zone and persistent
          corroboration cards so suggestions cannot visually masquerade as green verified facts. */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between"><div className="flex items-start gap-4"><div className="grid h-11 w-11 shrink-0 place-items-center rounded-2xl border border-violet-400/20 bg-violet-400/[0.07] text-violet-300"><Sparkles size={20} /></div><div><div className="eyebrow">Evidence-constrained reasoning</div><h3 className="mt-2 text-base font-medium text-white">MiniMax 证据补充线索</h3><div className="mt-2 inline-flex items-center gap-1.5 rounded-full border border-amber-300/15 bg-amber-300/[0.05] px-2.5 py-1 text-[9px] text-amber-200"><ShieldCheck size={12} />模型建议不是已验证事实</div><p className="mt-3 max-w-2xl text-xs leading-6 text-slate-500">仅发送有界、脱敏的 Catalog 证据摘要。建议必须引用现有 Evidence ID，并在确定性分析器提供独立佐证前保持 proposal-only。</p></div></div><button type="button" onClick={() => void submitReasoning()} disabled={!reasoningCapability?.enabled || reasoningBusy || ['queued', 'running'].includes(reasoningRun?.status || '')} className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl border border-violet-400/20 bg-violet-400/[0.08] px-4 py-2.5 text-xs text-violet-200 transition hover:bg-violet-400/[0.13] disabled:cursor-not-allowed disabled:opacity-35">{reasoningBusy || ['queued', 'running'].includes(reasoningRun?.status || '') ? <LoaderCircle size={15} className="animate-spin" /> : <Sparkles size={15} />}使用 MiniMax 补充分析线索</button></div>
      {reasoningCapability && !reasoningCapability.enabled && <div className="mt-5 rounded-xl border border-white/[0.06] bg-black/20 px-4 py-3 text-xs text-slate-600">当前服务未配置 MiniMax；确定性 Catalog 与 Graph 不受影响。</div>}
      {reasoningRun && <div className="mt-6"><div className="flex flex-wrap items-center gap-3 text-[10px] text-slate-600"><span>状态 <b className="font-mono font-normal text-violet-200">{reasoningRun.status}</b></span><span>尝试 #{reasoningRun.attempt}</span><span>建议 {reasoningRun.proposals.length}</span><span>拒绝 {reasoningRun.rejected_proposal_count}</span><span>Tokens {reasoningRun.prompt_tokens + reasoningRun.completion_tokens}</span>{reasoningRun.response_model && <span>模型 {reasoningRun.response_model}</span>}</div><div className="mt-4 grid gap-3 lg:grid-cols-2">{reasoningRun.proposals.map((proposal) => <article key={proposal.proposal_id} className="rounded-2xl border border-violet-400/10 bg-black/20 p-4"><div className="flex items-center justify-between gap-3"><span className="rounded-full bg-violet-400/[0.08] px-2 py-1 text-[9px] uppercase tracking-[0.08em] text-violet-300">{proposal.kind}</span><span className="font-mono text-[9px] text-slate-700">{Math.round(proposal.confidence * 100)}%</span></div><h4 className="mt-3 text-sm text-slate-200">{proposal.summary}</h4><p className="mt-2 text-[11px] leading-5 text-slate-500">{proposal.rationale}</p><div className="mt-4 rounded-xl border border-signal/10 bg-signal/[0.035] px-3 py-2.5"><div className="text-[9px] uppercase tracking-[0.1em] text-signal/70">仍需确定性佐证</div><div className="mt-1.5 text-[10px] leading-5 text-slate-400">{proposal.required_corroboration}</div></div><div className="mt-3 text-[9px] text-slate-700">引用 {proposal.cited_evidence_ids.length} 个既有 Evidence ID</div></article>)}</div>{reasoningRun.status === 'failed' && <div className="mt-4 rounded-xl border border-ember/20 bg-ember/[0.05] px-4 py-3 text-xs text-ember">模型补充失败：{reasoningRun.error_code || 'unknown'}。确定性分析结果保持可用。</div>}</div>}
    </section>}
  </div>
}

function JobDatum({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) { return <div className="flex items-start justify-between gap-4 text-[10px]"><span className="shrink-0 text-slate-600">{label}</span><span className={`break-all text-right text-slate-300 ${mono ? 'font-mono text-[9px]' : ''}`}>{value}</span></div> }

function formatBytes(value: number) { if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(0)} MiB`; if (value >= 1024) return `${(value / 1024).toFixed(0)} KiB`; return `${value} B` }

function SnapshotComparisonWorkspace({
  catalogs, baseCatalogId, targetCatalogId, onBaseCatalog, onTargetCatalog,
  result, selected, onSelect, loading,
}: {
  catalogs: MappingCatalogSummary[]
  baseCatalogId: string
  targetCatalogId: string
  onBaseCatalog: (value: string) => void
  onTargetCatalog: (value: string) => void
  result: MappingSnapshotDiff | null
  selected: MappingSnapshotChange | null
  onSelect: (value: MappingSnapshotChange) => void
  loading: boolean
}) {
  const [changeQuery, setChangeQuery] = useState('')
  const [changeCategory, setChangeCategory] = useState('')
  if (catalogs.length < 2) return <div className="grid min-h-[440px] place-items-center rounded-2xl border border-white/[0.07] bg-[#0a0f17]/75 p-8 text-center"><div><GitCompareArrows className="mx-auto text-cyan/35" size={38} /><h2 className="mt-4 text-sm text-slate-300">至少需要两个测绘目录</h2><p className="mt-2 text-xs text-slate-600">发布同型号的两个固件快照后才能比较通信结构。</p></div></div>
  const summary = result?.summary
  const structuralAdded = (summary?.added_candidate_count ?? 0) + (summary?.added_parameter_count ?? 0)
  const structuralRemoved = (summary?.removed_candidate_count ?? 0) + (summary?.removed_parameter_count ?? 0)
  const structuralChanged = (summary?.changed_candidate_count ?? 0) + (summary?.changed_parameter_count ?? 0)
  const normalizedChangeQuery = changeQuery.trim().toLocaleLowerCase()
  const visibleChanges = result?.changes.filter((item) => (
    (!changeCategory || item.category === changeCategory)
    && (!normalizedChangeQuery || `${item.display_identity} ${item.stable_identity}`.toLocaleLowerCase().includes(normalizedChangeQuery))
  )) ?? []
  const changeFilters = [
    ['', '全部'], ['candidate', '接口 / 候选'], ['parameter', '参数'],
    ['coverage', '覆盖'], ['potential_hidden_interface', '潜在隐藏'],
  ]
  return <div className="detail-enter space-y-4">
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <SignalMetric icon={<Plus size={16} />} label="新增结构" value={structuralAdded} />
      <SignalMetric icon={<Minus size={16} />} label="移除结构" value={structuralRemoved} />
      <SignalMetric icon={<GitCompareArrows size={16} />} label="结构变化" value={structuralChanged} />
      <SignalMetric icon={<EyeOff size={16} />} label="潜在隐藏新增" value={summary?.discovered_hidden_interface_count ?? 0} />
    </div>
    {result?.comparison_status === 'coverage_confounded' && <div className="flex items-start gap-3 rounded-xl border border-amber-400/20 bg-amber-400/[0.045] px-4 py-3"><TriangleAlert size={16} className="mt-0.5 shrink-0 text-amber-300" /><div><div className="text-xs font-medium text-amber-200">覆盖不可直接比较</div><p className="mt-1 text-[10px] leading-5 text-slate-500">Producer、版本、范围或完成状态不同。所有结构变化均降级为覆盖混杂，不能直接解释为固件代码变化。</p></div></div>}
    {result?.comparison_status === 'coverage_equivalent_partial' && <div className="flex items-start gap-3 rounded-xl border border-cyan/15 bg-cyan/[0.035] px-4 py-3"><TriangleAlert size={16} className="mt-0.5 shrink-0 text-cyan" /><div><div className="text-xs font-medium text-cyan">覆盖一致但不完整</div><p className="mt-1 text-[10px] leading-5 text-slate-500">两个版本使用相同分析范围，但至少一个必需范围仍为 partial；差异仅在已观察范围内成立。</p></div></div>}
    <div className="grid min-h-[620px] overflow-hidden rounded-2xl border border-white/[0.07] bg-[#0a0f17]/80 backdrop-blur-xl xl:grid-cols-[300px_minmax(360px,0.9fr)_minmax(420px,1.1fr)]">
      <aside className="border-b border-white/[0.07] p-5 xl:border-b-0 xl:border-r">
        <div className="eyebrow"><GitCompareArrows size={12} /> Snapshot alignment</div>
        <p className="mt-2 text-[10px] leading-5 text-slate-600">按稳定实体身份对齐，不使用 Evidence ID 或二进制地址漂移冒充接口变化。</p>
        <SnapshotSelect label="基线目录" value={baseCatalogId} catalogs={catalogs} onChange={onBaseCatalog} />
        <SnapshotSelect label="目标目录" value={targetCatalogId} catalogs={catalogs} onChange={onTargetCatalog} />
        <div className={`mt-5 rounded-xl border p-3 ${result?.same_firmware_family_verified ? 'border-signal/15 bg-signal/[0.035]' : 'border-cyan/10 bg-cyan/[0.025]'}`}><div className={`text-[9px] uppercase tracking-[0.12em] ${result?.same_firmware_family_verified ? 'text-signal' : 'text-cyan'}`}>{result?.same_firmware_family_verified ? '同固件族身份已验证' : '比较边界'}</div><p className="mt-2 text-[10px] leading-5 text-slate-500">{result?.same_firmware_family_verified ? `${result.base.release_context?.device_model} · ${result.base.release_context?.firmware_version} → ${result.target.release_context?.firmware_version}` : '当前目录只携带制品身份，不能断言同型号版本谱系。需由 Firmware Release 关系单独证明。'}</p></div>
        <div className="mt-5 space-y-2 text-[10px] text-slate-600"><div className="flex justify-between"><span>全部变化</span><span className="font-mono text-slate-300">{summary?.total_change_count ?? 0}</span></div><div className="flex justify-between"><span>Coverage 变化</span><span className="font-mono text-amber-300">{summary?.coverage_change_count ?? 0}</span></div><div className="flex justify-between"><span>潜在隐藏消失</span><span className="font-mono text-signal">{summary?.resolved_hidden_interface_count ?? 0}</span></div></div>
      </aside>
      <div className="border-b border-white/[0.07] xl:border-b-0 xl:border-r">
        <div className="border-b border-white/[0.07] p-4"><div className="flex items-center justify-between"><div className="text-[10px] uppercase tracking-[0.13em] text-slate-500">结构变化时间线</div><div className="font-mono text-[9px] text-slate-700">{visibleChanges.length} / {result?.changes.length ?? 0}</div></div><label className="search-field mt-3"><Search size={14} /><input aria-label="搜索版本差异" placeholder="搜索接口、RPC operation 或稳定身份…" value={changeQuery} onChange={(event) => setChangeQuery(event.target.value)} /></label><div className="mt-3 flex gap-2 overflow-x-auto pb-1">{changeFilters.map(([value, label]) => <button key={value} type="button" onClick={() => setChangeCategory(value)} className={`shrink-0 rounded-lg border px-2.5 py-1.5 text-[9px] transition ${changeCategory === value ? 'border-cyan/25 bg-cyan/[0.08] text-cyan' : 'border-white/[0.06] text-slate-600 hover:text-slate-300'}`}>{label}</button>)}</div></div>
        <div className="max-h-[560px] overflow-y-auto p-2">
          {loading && <div className="p-8 text-center text-xs text-slate-600">正在对齐两个不可变目录…</div>}
          {!loading && !visibleChanges.length && <div className="p-8 text-center text-xs text-slate-600">当前筛选范围没有观察到结构差异</div>}
          {visibleChanges.map((item) => <button key={item.change_id} type="button" aria-label={`查看版本差异 ${item.display_identity}`} onClick={() => onSelect(item)} className={`group mb-1 w-full rounded-xl border p-3 text-left transition ${selected?.change_id === item.change_id ? 'border-cyan/25 bg-cyan/[0.055]' : 'border-transparent hover:border-white/[0.06] hover:bg-white/[0.025]'}`}><div className="flex items-start gap-3"><ChangeGlyph kind={item.change_kind} /><div className="min-w-0 flex-1"><div className="truncate font-mono text-xs text-slate-200">{item.display_identity}</div><div className="mt-1 flex flex-wrap gap-2 text-[8px] uppercase tracking-[0.08em]"><span className="text-cyan/65">{item.category.replaceAll('_', ' ')}</span><span className={item.confidence === 'firmware_change_supported' ? 'text-signal' : 'text-amber-300'}>{item.confidence.replaceAll('_', ' ')}</span></div></div><ChevronRight size={14} className="mt-2 text-slate-700 transition group-hover:translate-x-0.5 group-hover:text-cyan" /></div></button>)}
        </div>
      </div>
      <div className="min-w-0 bg-[radial-gradient(circle_at_80%_10%,rgba(89,196,230,0.05),transparent_34%)]">{selected ? <SnapshotChangeEvidence item={selected} /> : <div className="grid h-full min-h-[420px] place-items-center p-8 text-center"><div><GitCompareArrows className="mx-auto text-cyan/35" size={36} /><h2 className="mt-4 text-sm font-medium text-slate-300">选择一条版本差异</h2><p className="mt-2 max-w-xs text-xs leading-5 text-slate-600">检查稳定身份、变化字段、基线/目标值与覆盖置信度。</p></div></div>}</div>
    </div>
  </div>
}

function SnapshotSelect({ label, value, catalogs, onChange }: { label: string; value: string; catalogs: MappingCatalogSummary[]; onChange: (value: string) => void }) { return <label className="mt-5 block"><span className="text-[9px] uppercase tracking-[0.12em] text-slate-600">{label}</span><select aria-label={label} value={value} onChange={(event) => onChange(event.target.value)} className="mt-2 w-full rounded-xl border border-white/[0.07] bg-[#080d14] px-3 py-2.5 font-mono text-[10px] text-slate-300 outline-none focus:border-cyan/30">{catalogs.map((catalog) => <option key={catalog.catalog_id} value={catalog.catalog_id}>{catalog.release_context ? `${catalog.release_context.device_model} · ${catalog.release_context.firmware_version}` : `${catalog.firmware_artifact_sha256.slice(0, 16)}…`} · {catalog.coverage_status}</option>)}</select></label> }

function ChangeGlyph({ kind }: { kind: MappingSnapshotChange['change_kind'] }) { const style = kind === 'added' ? 'bg-signal/[0.08] text-signal' : kind === 'removed' ? 'bg-ember/[0.08] text-ember' : 'bg-cyan/[0.08] text-cyan'; return <div className={`mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-lg ${style}`}>{kind === 'added' ? <Plus size={14} /> : kind === 'removed' ? <Minus size={14} /> : <GitCompareArrows size={14} />}</div> }

function SnapshotChangeEvidence({ item }: { item: MappingSnapshotChange }) { return <article className="detail-enter max-h-[650px] overflow-y-auto p-5 sm:p-6"><div className="eyebrow"><GitCompareArrows size={12} /> Version-aware evidence diff</div><h2 className="mt-3 break-all font-mono text-lg font-semibold text-white">{item.display_identity}</h2><div className="mt-3 flex flex-wrap gap-2"><span className="rounded-md border border-cyan/15 bg-cyan/[0.04] px-2 py-1 text-[9px] uppercase text-cyan">{item.change_kind}</span><span className={`rounded-md border px-2 py-1 text-[9px] uppercase ${item.confidence === 'firmware_change_supported' ? 'border-signal/15 bg-signal/[0.04] text-signal' : 'border-amber-400/15 bg-amber-400/[0.04] text-amber-300'}`}>{item.confidence.replaceAll('_', ' ')}</span></div><p className="mt-4 rounded-xl border border-white/[0.06] bg-white/[0.02] p-3 text-[10px] leading-5 text-slate-500">{item.interpretation}</p><EvidenceSection title="变化字段"><div className="flex flex-wrap gap-2">{item.changed_fields.map((field) => <span key={field} className="rounded-md bg-cyan/[0.06] px-2 py-1 font-mono text-[9px] text-cyan">{field}</span>)}</div></EvidenceSection><div className="grid gap-3 sm:grid-cols-2"><SnapshotValue title="BASE" value={item.base} /><SnapshotValue title="TARGET" value={item.target} /></div><EvidenceSection title="稳定身份"><div className="break-all font-mono text-[9px] leading-5 text-slate-600">{item.stable_identity}</div></EvidenceSection></article> }

function SnapshotValue({ title, value }: { title: string; value: Record<string, unknown> | null }) { return <div className="min-w-0 rounded-xl border border-white/[0.06] bg-black/20 p-3"><div className="text-[9px] uppercase tracking-[0.12em] text-slate-600">{title}</div>{value ? <div className="mt-3 space-y-2">{Object.entries(value).map(([key, entry]) => <div key={key}><div className="text-[8px] uppercase text-slate-700">{key}</div><div className="mt-0.5 break-all font-mono text-[9px] leading-4 text-slate-400">{typeof entry === 'string' ? entry : JSON.stringify(entry)}</div></div>)}</div> : <div className="mt-3 text-[10px] text-slate-700">不存在</div>}</div> }

function HiddenInterfaceWorkspace({ page, query, onQuery, selected, onSelect, loading }: {
  page: PotentialHiddenInterfacePage | null
  query: string
  onQuery: (value: string) => void
  selected: PotentialHiddenInterface | null
  onSelect: (value: PotentialHiddenInterface) => void
  loading: boolean
}) {
  const summary = page?.summary
  const maxFirmware = Math.max(1, ...(page?.distributions.firmware.map((item) => item.count) ?? [1]))
  return <div className="detail-enter space-y-4">
    {/* Design rationale: coverage gates are shown before candidate volume; a stable three-column
        investigation surface keeps distribution, ranking, and proof readable without drawers. */}
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <SignalMetric icon={<EyeOff size={16} />} label="潜在隐藏接口" value={page?.total ?? 0} />
      <SignalMetric icon={<Radar size={16} />} label="覆盖合格固件" value={summary?.eligible_firmware_count ?? 0} />
      <SignalMetric icon={<Binary size={16} />} label="关联 Handler" value={summary?.handler_count ?? 0} />
      <SignalMetric icon={<ShieldQuestion size={16} />} label="覆盖缺口固件" value={summary?.coverage_gap_firmware_count ?? 0} muted />
    </div>
    <div className="grid min-h-[610px] overflow-hidden rounded-2xl border border-white/[0.07] bg-[#0a0f17]/80 backdrop-blur-xl xl:grid-cols-[280px_minmax(360px,0.9fr)_minmax(420px,1.1fr)]">
      <aside className="border-b border-white/[0.07] p-5 xl:border-b-0 xl:border-r">
        <div className="eyebrow"><Radar size={12} /> 固件信号分布</div>
        <p className="mt-2 text-[10px] leading-5 text-slate-600">仅统计每个固件最新且前端、Native 差集覆盖完整的目录。</p>
        <div className="mt-5 space-y-4">
          {page?.distributions.firmware.map((item) => <div key={item.catalog_id}>
            <div className="flex items-center justify-between gap-2 text-[9px]"><span className="truncate font-mono text-slate-500">{item.firmware_artifact_sha256.slice(0, 12)}…</span><span className="font-mono text-signal">{item.count}</span></div>
            <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/[0.05]"><div className="h-full rounded-full bg-gradient-to-r from-cyan/60 to-signal shadow-[0_0_12px_rgba(183,243,107,0.3)] transition-all" style={{ width: `${Math.max(8, item.count / maxFirmware * 100)}%` }} /></div>
          </div>)}
          {!page?.distributions.firmware.length && <Muted />}
        </div>
        <div className="mt-7 border-t border-white/[0.06] pt-5"><div className="text-[9px] uppercase tracking-[0.14em] text-slate-600">处理主体</div><div className="mt-3 space-y-2">{page?.distributions.artifact.map((item) => <div key={item.path} className="rounded-lg border border-white/[0.05] bg-white/[0.02] p-2.5"><div className="break-all font-mono text-[9px] text-cyan">{item.path}</div><div className="mt-1 text-[9px] text-slate-600">{item.count} 个注册信号</div></div>)}</div></div>
      </aside>
      <div className="border-b border-white/[0.07] xl:border-b-0 xl:border-r">
        <div className="border-b border-white/[0.07] p-4"><label className="search-field"><Search size={15} /><input aria-label="搜索潜在隐藏接口" placeholder="搜索 operation、handler 或二进制…" value={query} onChange={(event) => onQuery(event.target.value)} /></label><div className="mt-3 flex items-center justify-between text-[9px] text-slate-600"><span>注册存在 · 前端引用未观察</span><span>{page?.total ?? 0} signals</span></div></div>
        <div className="max-h-[520px] overflow-y-auto p-2">
          {loading && <div className="p-8 text-center text-xs text-slate-600">正在计算跨固件信号…</div>}
          {!loading && !page?.items.length && <div className="p-8 text-center text-xs text-slate-600">当前完整覆盖目录中没有该类信号</div>}
          {page?.items.map((item) => <button key={item.interface_id} type="button" aria-label={`查看潜在隐藏接口 ${item.operation_token}`} onClick={() => onSelect(item)} className={`group mb-1 w-full rounded-xl border p-3 text-left transition ${selected?.interface_id === item.interface_id ? 'border-signal/25 bg-signal/[0.06]' : 'border-transparent hover:border-white/[0.06] hover:bg-white/[0.025]'}`}><div className="flex items-start gap-3"><div className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-signal/[0.07] text-signal"><EyeOff size={14} /></div><div className="min-w-0 flex-1"><div className="truncate font-mono text-xs text-slate-200">{item.operation_token}</div><div className="mt-1 truncate font-mono text-[9px] text-cyan/60">{item.registration_artifact_path}</div><div className="mt-2 flex gap-2 text-[8px] uppercase tracking-[0.08em] text-slate-600"><span>{item.handler_identities.length} handler</span><span>{item.evidence_ids.length} evidence</span></div></div><ChevronRight size={14} className="mt-2 text-slate-700 transition group-hover:translate-x-0.5 group-hover:text-signal" /></div></button>)}
        </div>
      </div>
      <div className="min-w-0 bg-[radial-gradient(circle_at_80%_10%,rgba(183,243,107,0.055),transparent_32%)]">{selected ? <HiddenInterfaceEvidence item={selected} /> : <div className="grid h-full min-h-[420px] place-items-center p-8 text-center"><div><EyeOff className="mx-auto text-signal/35" size={36} /><h2 className="mt-4 text-sm font-medium text-slate-300">选择一个潜在隐藏接口</h2><p className="mt-2 max-w-xs text-xs leading-5 text-slate-600">查看注册处理主体、handler、前端覆盖范围与仍需验证的运行时原因。</p></div></div>}</div>
    </div>
  </div>
}

function SignalMetric({ icon, label, value, muted = false }: { icon: React.ReactNode; label: string; value: number; muted?: boolean }) { return <div className="rounded-2xl border border-white/[0.07] bg-gradient-to-br from-white/[0.04] to-transparent p-4"><div className={`flex items-center gap-2 text-[10px] ${muted ? 'text-slate-600' : 'text-signal'}`}>{icon}<span className="uppercase tracking-[0.12em]">{label}</span></div><div className="mt-3 font-mono text-2xl font-semibold text-white">{value}</div></div> }

function HiddenInterfaceEvidence({ item }: { item: PotentialHiddenInterface }) { return <article className="detail-enter max-h-[640px] overflow-y-auto p-5 sm:p-6"><div className="eyebrow"><ShieldQuestion size={12} /> Potential hidden interface</div><h2 className="mt-3 break-all font-mono text-xl font-semibold text-white">{item.operation_token}</h2><div className="mt-4 rounded-xl border border-amber-400/15 bg-amber-400/[0.04] p-3"><div className="text-[10px] font-semibold text-amber-300">不是后门结论</div><p className="mt-1 text-[10px] leading-5 text-slate-500">该标签只说明原生注册已验证、声明的前端覆盖已完成，但未观察到引用；动态客户端、直连请求、废弃代码与运行时注册仍需验证。</p></div><EvidenceSection title="注册与处理主体"><div className="rounded-lg border border-cyan/15 bg-cyan/[0.035] p-3"><div className="break-all font-mono text-xs text-cyan">{item.registration_artifact_path}</div><div className="mt-3 space-y-2">{item.handler_identities.map((handler) => <div key={handler} className="break-all rounded-md bg-black/20 px-2.5 py-2 font-mono text-[10px] text-signal">{handler}</div>)}</div></div></EvidenceSection><EvidenceSection title="前端覆盖范围">{item.frontend_coverage_scopes.map((scope) => <div key={scope} className="rounded-lg border border-white/[0.06] p-3 font-mono text-[10px] text-slate-400">{scope}</div>)}</EvidenceSection><EvidenceSection title="未决原因义务"><div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-[10px] leading-5 text-slate-500">{item.open_obligation}</div></EvidenceSection><EvidenceSection title="证据身份"><div className="space-y-1.5">{item.evidence_ids.map((id) => <div key={id} className="break-all font-mono text-[8px] leading-4 text-slate-700">{id}</div>)}</div></EvidenceSection></article> }

function StatusPill({ catalog }: { catalog: MappingCatalogSummary }) {
  return <div className="flex items-center gap-3 rounded-xl border border-white/[0.07] bg-white/[0.025] px-4 py-3"><Activity size={16} className="text-signal" /><div><div className="text-[9px] uppercase tracking-[0.16em] text-slate-600">Latest coverage</div><div className="mt-1 text-xs text-slate-300">{catalog.coverage_status} · {catalog.candidate_count} candidates</div><div className="mt-1 text-[9px] uppercase tracking-[0.1em] text-slate-600">Inventory {catalog.source_inventory_coverage_status}</div></div></div>
}

function CandidateRow({ candidate, active, onClick }: { candidate: MappingCandidate; active: boolean; onClick: () => void }) {
  return <button type="button" onClick={onClick} aria-label={`查看候选 ${candidate.canonical_identity}`} className={`group mb-1 flex w-full items-center gap-3 rounded-xl border px-3 py-3 text-left transition ${active ? 'border-signal/20 bg-signal/[0.06]' : 'border-transparent hover:border-white/[0.06] hover:bg-white/[0.025]'}`}>
    <div className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-cyan/[0.07] text-cyan"><Braces size={15} /></div><div className="min-w-0 flex-1"><div className="truncate font-mono text-xs text-slate-200">{candidate.canonical_identity}</div><div className="mt-1 flex gap-2 text-[9px] uppercase tracking-[0.09em] text-slate-600"><span>{candidate.candidate_kind.replaceAll('_', ' ')}</span><span>{candidate.parameter_count} params</span><span>{candidate.association_count} links</span></div></div><ChevronRight size={14} className="text-slate-700 transition group-hover:translate-x-0.5 group-hover:text-signal" />
  </button>
}

function CandidateEvidence({ detail }: { detail: MappingCandidateDetail }) {
  const item = detail.candidate
  const attributes = Object.fromEntries(item.attributes)
  const isUrlIpc = item.candidate_kind === 'native_configuration_url_ipc_flow'
  const isUrlConsumer = item.candidate_kind === 'native_configuration_url_consumer'
  const isCgiSelector = item.candidate_kind === 'native_cgi_selector'
  const title = item.candidate_kind === 'candidate_association'
    ? '跨层候选关联'
    : item.canonical_identity
  return <article className="detail-enter max-h-[640px] overflow-y-auto p-5 sm:p-6">
    <div className="eyebrow"><FileCode2 size={12} /> Evidence detail</div><h2 className="mt-3 break-all font-mono text-lg font-semibold text-white">{title}</h2><p className="mt-2 break-all text-xs text-slate-600">{item.source_path} · {item.source_construct}</p>
    {item.candidate_kind === 'candidate_association' && <p className="mt-2 break-all font-mono text-[9px] leading-4 text-slate-700">{item.canonical_identity}</p>}
    {isUrlIpc && <div className="mt-4 rounded-xl border border-cyan/20 bg-cyan/[0.045] p-3"><div className="text-[10px] font-semibold text-cyan">URL 配置 IPC</div><p className="mt-1 font-mono text-[10px] leading-5 text-slate-400">{attributes.channel_path} · {attributes.message_size} bytes · opcode@0 · key/path@{attributes.key_offset || '—'} · value@{attributes.value_offset || '—'}</p><p className="mt-1 text-[10px] text-slate-600">{attributes.operation} · request {attributes.request_opcode} · response {attributes.response_opcodes} · {attributes.access_mode}_state</p></div>}
    {isUrlConsumer && <div className="mt-4 rounded-xl border border-amber-300/20 bg-amber-300/[0.04] p-3"><div className="text-[10px] font-semibold text-amber-200">按调用点绑定状态域</div><p className="mt-1 text-[10px] leading-5 text-slate-500">这里只展示经 URL client 调用绑定的 key template；同前缀的 rule.* / flag 属主 CFM，name 仍未绑定，不能按前缀合并。</p></div>}
    {isCgiSelector && <div className="mt-4 rounded-xl border border-emerald-300/20 bg-emerald-300/[0.04] p-3"><div className="text-[10px] font-semibold text-emerald-200">CGI 组合式路由</div><p className="mt-1 font-mono text-[10px] leading-5 text-slate-400">{attributes.interface_path} · {attributes.interface_path_status}</p><p className="mt-1 text-[10px] leading-5 text-slate-500">由 namespace registrar、path 第二段解析和 selector compare arm 共同证明；不是完整 URL 字面量。HTTP method 为 {attributes.method_status || 'unresolved'}，不会根据上传 body 猜测 POST。</p><div className="mt-2 flex flex-wrap gap-1.5"><span className="rounded bg-black/20 px-2 py-1 font-mono text-[9px] text-cyan">selector {attributes.selector}</span><span className="rounded bg-black/20 px-2 py-1 font-mono text-[9px] text-cyan">compare {attributes.comparison_width} bytes</span><span className="rounded bg-black/20 px-2 py-1 font-mono text-[9px] text-cyan">handler {attributes.handler_address}</span></div></div>}
    <div className="mt-5 grid grid-cols-3 gap-2">{[['参数', detail.parameters.length], ['关联', detail.associations.length + detail.related_candidates.length], ['未决', detail.open_obligations.length]].map(([label, value]) => <div key={label} className="rounded-xl border border-white/[0.06] bg-black/20 p-3"><div className="text-[9px] text-slate-600">{label}</div><div className="mt-1 text-lg font-semibold text-slate-200">{value}</div></div>)}</div>
    <EvidenceSection title="架构与分析属性">{item.attributes.length ? <div className="grid gap-2 sm:grid-cols-2">{item.attributes.map(([key, value]) => <div key={`${key}:${value}`} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3"><div className="text-[9px] uppercase tracking-[0.08em] text-slate-600">{key.replaceAll('_', ' ')}</div><div className="mt-1 break-all font-mono text-[10px] leading-5 text-cyan">{value}</div></div>)}</div> : <Muted />}</EvidenceSection>
    <EvidenceSection title="参数与操作选择器">{detail.parameters.length ? detail.parameters.map((parameter) => <div key={parameter.parameter_id} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3"><div className="font-mono text-xs text-cyan">{parameter.name}</div><div className="mt-1 text-[10px] text-slate-600">{parameter.namespace}{parameter.is_operation_selector ? ' · operation selector' : ''}{parameter.literal_value ? ` · ${parameter.literal_value}` : ''}</div></div>) : <Muted />}</EvidenceSection>
    <EvidenceSection title="跨层关联">{detail.associations.length ? detail.associations.map((association) => <div key={association.association_id} className="rounded-lg border border-signal/10 bg-signal/[0.035] p-3 text-xs text-slate-400"><span className="text-signal">{association.match_basis}</span><div className="mt-1 break-all font-mono text-[9px] text-slate-600">{association.native_hint_id}</div></div>) : <Muted />}</EvidenceSection>
    <EvidenceSection title="后端执行与访问链">{detail.related_candidates.length ? detail.related_candidates.map((related) => <RelatedCandidateCard key={related.candidate_id} candidate={related} />) : <Muted />}</EvidenceSection>
    <EvidenceSection title="未决分析义务">{detail.open_obligations.length ? detail.open_obligations.map((obligation) => <div key={obligation.obligation_id} className="rounded-lg border border-amber-400/15 bg-amber-400/[0.035] p-3"><div className="flex items-start justify-between gap-3"><span className="font-mono text-[10px] text-amber-300">{obligation.required_capability ?? obligation.status}</span><span className="text-[8px] uppercase tracking-[0.1em] text-slate-600">{obligation.priority ? `P${obligation.priority}` : obligation.status}</span></div><p className="mt-2 text-[10px] leading-5 text-slate-500">{obligation.reason}</p>{obligation.candidate_analyzers?.length ? <div className="mt-2 flex flex-wrap gap-1.5">{obligation.candidate_analyzers.map((analyzer) => <span key={analyzer} className="rounded bg-black/20 px-2 py-1 font-mono text-[8px] text-slate-600">{analyzer}</span>)}</div> : null}</div>) : <Muted />}</EvidenceSection>
    <EvidenceSection title="原始证据位置">{detail.evidence_atoms.map((atom) => <div key={atom.evidence_id} className="rounded-lg border border-white/[0.06] p-3"><div className="text-[10px] text-slate-400">{atom.capability}</div><div className="mt-1 break-all font-mono text-[9px] leading-5 text-slate-600">{atom.source_span.artifact_path} · {atom.source_span.locator}</div></div>)}</EvidenceSection>
  </article>
}

function RelatedCandidateCard({ candidate }: { candidate: MappingCandidate }) {
  const attributes = Object.fromEntries(candidate.attributes)
  const isPolicy = candidate.candidate_kind === 'ubus_access_grant'
  const isPrincipal = candidate.candidate_kind === 'runtime_principal'
  const status = isPolicy
    ? `${attributes.access_mode ?? ''} · ${attributes.policy_group ?? ''}`
    : isPrincipal ? attributes.principal_kind ?? candidate.claim_status
      : attributes.binding_status ?? candidate.claim_status
  return <div className={`rounded-lg border p-3 ${isPolicy ? 'border-violet-400/15 bg-violet-400/[0.035]' : isPrincipal ? 'border-signal/15 bg-signal/[0.035]' : 'border-cyan/15 bg-cyan/[0.035]'}`}>
    <div className="flex items-start justify-between gap-3"><span className={`break-all font-mono text-xs ${isPolicy ? 'text-violet-300' : isPrincipal ? 'text-signal' : 'text-cyan'}`}>{candidate.canonical_identity}</span><span className="shrink-0 text-[8px] uppercase tracking-[0.1em] text-slate-500">{status}</span></div>
    <div className="mt-1 break-all text-[9px] text-slate-600">{candidate.candidate_kind.replaceAll('_', ' ')} · {candidate.source_path}</div>
    {attributes.object_pattern && <div className="mt-2 font-mono text-[9px] text-violet-300/70">object {attributes.object_pattern}</div>}
    {attributes.parameter_names && <div className="mt-2 font-mono text-[9px] text-cyan/70">params {attributes.parameter_names}</div>}
    {attributes.handler_identity && <div className="mt-2 font-mono text-[9px] text-emerald-300/70">handler {attributes.handler_identity}</div>}
  </div>
}

function EvidenceSection({ title, children }: { title: string; children: React.ReactNode }) { return <section className="mt-6"><h3 className="mb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">{title}</h3><div className="space-y-2">{children}</div></section> }
function Muted() { return <div className="rounded-lg border border-dashed border-white/[0.06] p-3 text-[10px] text-slate-700">当前目录未发布该类事实</div> }
function EmptyCatalog() { return <div className="rounded-2xl border border-dashed border-white/[0.08] bg-white/[0.015] p-14 text-center"><Database className="mx-auto text-slate-700" /><h2 className="mt-4 text-sm text-slate-300">尚未发布测绘目录</h2><p className="mt-2 text-xs text-slate-600">完成 Producer Batch、关联和义务调度后，通过持久化接口发布目录。</p></div> }
