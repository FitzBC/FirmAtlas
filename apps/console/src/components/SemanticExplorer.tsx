import {
  ArrowLeft, ArrowRight, BarChart3, Boxes, Braces, CircuitBoard,
  Layers3, LoaderCircle, Network, Search, ShieldAlert, Sparkles, X,
} from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { intelligenceApi } from '../api/client'
import { formatRelativeTime, severityTone } from '../lib/format'
import type {
  SemanticAssociation, SemanticCatalogItem, SemanticCategory,
  SemanticCategoryProfile, SemanticExploreKind, SemanticExplorePage, Vulnerability,
  InterfaceStructureRecommendation,
} from '../types'
import { useDebouncedValue } from '../hooks/useDebouncedValue'
import { PaginationControls } from './PaginationControls'
import { VulnerabilityDetail } from './VulnerabilityDetail'

interface SemanticExplorerProps {
  mode: SemanticExploreKind
}

const categoryColors: Record<string, string> = {
  form_handler: '#b8f36a', cgi_gateway: '#ff7d5c', hnap_soap: '#a78bfa',
  resource_api: '#56cfee', web_action: '#60a5fa', rpc_command: '#f5b942',
  management_route: '#64748b',
}

export function SemanticExplorer({ mode }: SemanticExplorerProps) {
  const [catalog, setCatalog] = useState<SemanticExplorePage<SemanticCatalogItem> | null>(null)
  const [categories, setCategories] = useState<SemanticCategory[]>([])
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<string | null>(null)
  const [selectedKind, setSelectedKind] = useState<'interface' | 'parameter'>('interface')
  const [detail, setDetail] = useState<SemanticExplorePage<SemanticAssociation> | null>(null)
  const [detailPage, setDetailPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [detailLoading, setDetailLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null)
  const [categoryDetail, setCategoryDetail] = useState<SemanticExplorePage<SemanticCatalogItem> | null>(null)
  const [categoryQuery, setCategoryQuery] = useState('')
  const [categorySubtype, setCategorySubtype] = useState('')
  const [categoryPage, setCategoryPage] = useState(1)
  const [categoryLoading, setCategoryLoading] = useState(false)
  const debouncedQuery = useDebouncedValue(query, 220)
  const debouncedCategoryQuery = useDebouncedValue(categoryQuery, 220)

  useEffect(() => {
    setPage(1); setSelected(null); setDetail(null); setQuery(''); setSelectedCategory(null)
  }, [mode])

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true); setError(null)
    if (mode === 'category') {
      void intelligenceApi.semanticCategories()
        .then((result) => setCategories(result.items))
        .catch((caught) => setError(caught instanceof Error ? caught.message : '无法读取接口类别'))
        .finally(() => setLoading(false))
    } else {
      void intelligenceApi.semanticExplore(mode, page, debouncedQuery, '', controller.signal)
        .then((result) => setCatalog(result as SemanticExplorePage<SemanticCatalogItem>))
        .catch((caught) => {
          if (!(caught instanceof DOMException && caught.name === 'AbortError')) {
            setError(caught instanceof Error ? caught.message : '无法读取语义明细')
          }
        })
        .finally(() => setLoading(false))
    }
    return () => controller.abort()
  }, [mode, page, debouncedQuery])

  useEffect(() => {
    if (!selected) return
    const controller = new AbortController()
    setDetailLoading(true)
    void intelligenceApi.semanticExplore(selectedKind, detailPage, '', selected, controller.signal)
      .then((result) => setDetail(result as SemanticExplorePage<SemanticAssociation>))
      .catch((caught) => {
        if (!(caught instanceof DOMException && caught.name === 'AbortError')) {
          setError(caught instanceof Error ? caught.message : '无法读取关联漏洞')
        }
      })
      .finally(() => setDetailLoading(false))
    return () => controller.abort()
  }, [selectedKind, selected, detailPage])

  useEffect(() => {
    if (!selectedCategory) return
    const controller = new AbortController()
    setCategoryLoading(true)
    void intelligenceApi.semanticExplore('category', categoryPage, debouncedCategoryQuery, selectedCategory, controller.signal, categorySubtype)
      .then((result) => setCategoryDetail(result as SemanticExplorePage<SemanticCatalogItem>))
      .catch((caught) => {
        if (!(caught instanceof DOMException && caught.name === 'AbortError')) {
          setError(caught instanceof Error ? caught.message : '无法读取类别接口')
        }
      })
      .finally(() => setCategoryLoading(false))
    return () => controller.abort()
  }, [selectedCategory, categoryPage, debouncedCategoryQuery, categorySubtype])

  const open = (kind: 'interface' | 'parameter', value: string) => { setSelectedKind(kind); setSelected(value); setDetailPage(1); setDetail(null) }
  const openCategory = (value: string) => { setSelectedCategory(value); setCategoryPage(1); setCategoryQuery(''); setCategorySubtype(''); setCategoryDetail(null) }

  return (
    <section className="mt-4">
      {error && <div role="alert" className="mb-4 rounded-xl border border-ember/20 bg-ember/[0.06] px-4 py-3 text-xs text-ember">{error}</div>}
      {mode === 'category'
        ? <><InterfaceStructureSearch onSelectInterface={(value) => open('interface', value)} /><CategoryAtlas categories={categories} loading={loading} onSelect={openCategory} /></>
        : (
          <>
            <div className="mb-4 flex flex-col gap-3 rounded-[20px] border border-white/[0.07] bg-white/[0.025] p-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <div className="eyebrow">{mode === 'interface' ? <Network size={13} /> : <Braces size={13} />} Deep inventory</div>
                <h2 className="mt-2 text-lg font-semibold text-white">{mode === 'interface' ? '全部暴露接口' : '全部接口参数'}</h2>
                <p className="mt-1 text-[11px] text-slate-600">点击任一观察事实，查看关联漏洞、厂商、标准固件型号与版本边界。</p>
              </div>
              <label className="search-field w-full sm:w-[300px]">
                <Search size={15} /><span className="sr-only">搜索语义明细</span>
                <input value={query} onChange={(event) => { setQuery(event.target.value); setPage(1) }} placeholder={mode === 'interface' ? '搜索接口或组件…' : '搜索参数或安全影响…'} />
              </label>
            </div>
            <CatalogTable mode={mode} page={catalog} loading={loading} onSelect={(value) => open(mode, value)} onPage={setPage} />
          </>
        )}
      {selected && (
        <AssociationDrawer
          kind={selectedKind} value={selected} page={detail} loading={detailLoading}
          onClose={() => setSelected(null)} onPage={setDetailPage}
          parentLabel={selectedCategory ? String(categoryDetail?.selection?.label || selectedCategory) : undefined}
        />
      )}
      {selectedCategory && (
        <CategoryDrawer
          category={selectedCategory} page={categoryDetail} loading={categoryLoading}
          query={categoryQuery} subtype={categorySubtype}
          onQuery={(value) => { setCategoryQuery(value); setCategoryPage(1) }}
          onSubtype={(value) => { setCategorySubtype(value); setCategoryPage(1) }}
          onPage={setCategoryPage} onSelectInterface={(value) => open('interface', value)}
          onClose={() => setSelectedCategory(null)}
          shifted={Boolean(selected)}
        />
      )}
    </section>
  )
}

function CatalogTable({ mode, page, loading, onSelect, onPage }: {
  mode: 'interface' | 'parameter'; page: SemanticExplorePage<SemanticCatalogItem> | null
  loading: boolean; onSelect: (value: string) => void; onPage: (page: number) => void
}) {
  return (
    <div className="overflow-hidden rounded-[22px] border border-white/[0.08] bg-[#0e141d]/85 shadow-lift">
      <div className="grid grid-cols-[minmax(0,1fr)_90px] border-b border-white/[0.06] bg-white/[0.018] px-5 py-3 text-[9px] font-semibold uppercase tracking-[0.16em] text-slate-700 sm:grid-cols-[minmax(0,1fr)_160px_110px_100px]">
        <span>{mode === 'interface' ? 'Interface' : 'Parameter'}</span><span className="hidden sm:block">Style / context</span><span className="hidden sm:block">Vendors</span><span className="text-right">Vulnerabilities</span>
      </div>
      <div className="divide-y divide-white/[0.055]">
        {loading && !page ? Array.from({ length: 7 }, (_, index) => <div key={index} className="h-[74px] animate-pulse bg-white/[0.012]" />) : page?.items.map((item) => (
          <button type="button" key={item.value} onClick={() => onSelect(item.value)} className="group grid w-full grid-cols-[minmax(0,1fr)_90px] items-center gap-4 px-5 py-4 text-left transition hover:bg-white/[0.035] sm:grid-cols-[minmax(0,1fr)_160px_110px_100px]">
            <div className="min-w-0">
              <code className="block truncate text-xs font-semibold text-slate-200 group-hover:text-signal">{item.value}</code>
              <p className="mt-1.5 truncate text-[10px] text-slate-650">{mode === 'interface' ? [item.method, item.protocol, item.component].filter(Boolean).join(' · ') || '管理路由' : [item.interface_value, item.location, item.security_effect].filter(Boolean).join(' · ') || '未关联接口'}</p>
            </div>
            <StyleBadge category={item.category} />
            <div className="hidden sm:block"><div className="flex -space-x-1">{(item.vendors ?? []).slice(0, 3).map((vendor) => <span key={vendor} title={vendor} className="grid h-7 w-7 place-items-center rounded-full border border-[#111923] bg-[#1a2430] text-[8px] font-semibold text-slate-400">{vendor.slice(0, 2).toUpperCase()}</span>)}</div><span className="mt-1 block text-[9px] text-slate-700">{item.vendor_count} 家厂商</span></div>
            <div className="flex items-center justify-end gap-2"><div className="text-right"><strong className="font-mono text-sm text-white">{item.vulnerability_count}</strong><span className="block text-[8px] text-slate-700">{item.occurrence_count} 次观察</span></div><ArrowRight size={14} className="text-slate-700 transition group-hover:translate-x-0.5 group-hover:text-signal" /></div>
          </button>
        ))}
      </div>
      {page && <PaginationControls page={page.page} pages={page.pages} total={page.total} hasPrevious={page.has_previous} hasNext={page.has_next} onPage={onPage} />}
    </div>
  )
}

function InterfaceStructureSearch({ onSelectInterface }: { onSelectInterface: (value: string) => void }) {
  const [value, setValue] = useState('')
  const [submitted, setSubmitted] = useState('')
  const [result, setResult] = useState<InterfaceStructureRecommendation | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const run = (route: string, page = 1) => {
    const query = route.trim()
    if (!query) return
    const controller = new AbortController()
    setSubmitted(query); setLoading(true); setError(null)
    void intelligenceApi.recommendInterfaceStructure(query, page, controller.signal)
      .then(setResult)
      .catch((caught) => setError(caught instanceof Error ? caught.message : '无法分析该接口'))
      .finally(() => setLoading(false))
  }

  return (
    <article className="mb-4 overflow-hidden rounded-[24px] border border-signal/15 bg-gradient-to-br from-signal/[0.055] via-[#0e151e] to-cyan/[0.025] shadow-lift">
      <div className="grid gap-5 p-5 lg:grid-cols-[minmax(0,1fr)_420px] lg:items-end">
        <div><div className="eyebrow"><Search size={13} /> Interface structure query</div><h2 className="mt-2 text-xl font-semibold tracking-[-0.03em] text-white">输入接口，寻找相似后端通信结构</h2><p className="mt-2 max-w-2xl text-[10px] leading-5 text-slate-600">支持数据库中尚未出现的路径。系统先推断接口类别和后端架构风格，再关联同结构接口、漏洞、厂商与固件型号。</p></div>
        <form aria-label="接口结构查询" onSubmit={(event) => { event.preventDefault(); run(value) }} className="flex gap-2">
          <label className="search-field min-w-0 flex-1"><Network size={14} /><span className="sr-only">固件接口</span><input value={value} onChange={(event) => setValue(event.target.value)} placeholder="输入固件接口，例如 /goform/SetOnlineDevName" /></label>
          <button type="submit" disabled={!value.trim() || loading} className="rounded-xl border border-signal/20 bg-signal/[0.10] px-4 text-[10px] font-semibold text-signal transition hover:bg-signal/[0.16] disabled:opacity-40">{loading ? '分析中…' : '分析并推荐'}</button>
        </form>
      </div>
      {error && <div role="alert" className="mx-5 mb-5 rounded-xl border border-ember/20 bg-ember/[0.06] px-3 py-2 text-[10px] text-ember">{error}</div>}
      {result && <div className="border-t border-white/[0.065] p-5">
        <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_repeat(4,110px)]">
          <div className="rounded-2xl border border-white/[0.07] bg-black/15 p-4"><div className="flex flex-wrap items-center gap-2"><span className="rounded-lg bg-cyan/[0.08] px-2 py-1 text-[9px] text-cyan">{result.selection.category.label}</span><ArrowRight size={12} className="text-slate-700" /><strong className="text-xs text-signal">{result.selection.architecture.label}</strong><span className="rounded bg-white/[0.04] px-1.5 py-1 text-[8px] text-slate-600">{result.selection.observed ? '已有观察' : '路径推断'}</span></div><p className="mt-2 text-[9px] leading-4 text-slate-650">{result.selection.architecture.description}</p><p className="mt-2 text-[8px] text-slate-750">结构相似性推荐，不构成代码同源或组件身份结论。</p></div>
          <MiniStatCard label="相似接口" value={result.scope.interface_count} /><MiniStatCard label="关联漏洞" value={result.scope.vulnerability_count} /><MiniStatCard label="厂商" value={result.scope.vendor_count} /><MiniStatCard label="固件型号" value={result.scope.model_count} />
        </div>
        <div className="mt-4 grid gap-4 xl:grid-cols-[1.15fr_.85fr]">
          <section className="overflow-hidden rounded-2xl border border-white/[0.07] bg-black/10"><div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-3"><div className="eyebrow"><Network size={12} /> Recommended interfaces</div><span className="font-mono text-[9px] text-slate-700">{result.total} matches</span></div><div className="divide-y divide-white/[0.05]">{result.items.map((item) => <button type="button" key={item.value} onClick={() => onSelectInterface(item.value)} className="grid w-full grid-cols-[minmax(0,1fr)_70px] items-center gap-3 px-4 py-3 text-left transition hover:bg-white/[0.035]"><div className="min-w-0"><code className="block truncate text-[11px] font-semibold text-slate-200">{item.value}</code><p className="mt-1 truncate text-[8px] text-slate-650">{item.similarity_signals.join(' · ')}</p><div className="mt-1.5 flex flex-wrap gap-1">{item.vendors.map((vendor) => <span key={vendor} className="rounded bg-white/[0.035] px-1.5 py-0.5 text-[8px] text-slate-500">{vendor}</span>)}</div></div><div className="text-right"><strong className="font-mono text-sm text-signal">{item.similarity_score}</strong><span className="block text-[7px] uppercase text-slate-700">similarity</span><span className="mt-1 block text-[8px] text-slate-600">{item.vulnerability_count} 漏洞</span></div></button>)}</div>{result.pages > 1 && <PaginationControls page={result.page} pages={result.pages} total={result.total} hasPrevious={result.has_previous} hasNext={result.has_next} onPage={(page) => run(submitted, page)} />}</section>
          <div className="space-y-3">
            <section className="rounded-2xl border border-white/[0.07] bg-black/10 p-4"><div className="eyebrow"><BarChart3 size={12} /> Related vendors & firmware</div><div className="mt-3 flex flex-wrap gap-1.5">{result.related_vendors.slice(0, 8).map((item) => <span key={item.vendor} className="rounded-lg border border-white/[0.06] bg-white/[0.025] px-2 py-1 text-[8px] text-slate-400">{item.vendor} · {item.model_count} 型号</span>)}</div><div className="mt-3 grid gap-1.5 sm:grid-cols-2">{result.related_firmware.slice(0, 6).map((item) => <div key={item.key} className="rounded-lg bg-white/[0.025] p-2"><strong className="block truncate text-[9px] text-slate-300">{item.label}</strong><span className="mt-1 block truncate font-mono text-[8px] text-cyan/70">{item.version_summary}</span></div>)}</div></section>
            <section className="rounded-2xl border border-white/[0.07] bg-black/10 p-4"><div className="eyebrow"><ShieldAlert size={12} /> Representative vulnerabilities</div><div className="mt-3 space-y-2">{result.related_vulnerabilities.slice(0, 5).map((item) => <article key={item.identifier} className="rounded-lg border border-white/[0.05] bg-white/[0.02] p-2.5"><div className="flex items-center justify-between gap-2"><code className="text-[9px] font-semibold text-cyan">{item.identifier}</code><span className={`rounded px-1.5 py-0.5 text-[8px] ${severityTone(item.severity)}`}>{item.cvss_score ?? '—'}</span></div><p className="mt-1 truncate text-[9px] text-slate-400">{item.title}</p><span className="mt-1 block text-[8px] text-slate-700">{[item.vendor, item.product].filter((value) => value && value.toLowerCase() !== 'n/a').join(' · ') || '厂商/型号待补全'}</span></article>)}</div></section>
          </div>
        </div>
      </div>}
    </article>
  )
}

function CategoryAtlas({ categories, loading, onSelect }: { categories: SemanticCategory[]; loading: boolean; onSelect: (key: string) => void }) {
  const total = categories.reduce((sum, item) => sum + item.interface_count, 0)
  const gradient = useMemo(() => {
    let cursor = 0
    const stops = categories.map((item) => {
      const start = cursor; cursor += total ? item.interface_count / total * 100 : 0
      return `${categoryColors[item.key] || '#64748b'} ${start}% ${cursor}%`
    })
    return `conic-gradient(${stops.join(',') || '#1e293b 0 100%'})`
  }, [categories, total])
  if (loading) return <div className="grid min-h-80 place-items-center"><LoaderCircle className="animate-spin text-signal" /></div>
  return (
    <>
      <div className="grid gap-4 xl:grid-cols-[360px_minmax(0,1fr)]">
        <article className="relative overflow-hidden rounded-[26px] border border-white/[0.08] bg-gradient-to-br from-white/[0.055] to-transparent p-6 shadow-lift">
          <div className="eyebrow"><CircuitBoard size={13} /> Interface taxonomy</div>
          <h2 className="mt-3 text-2xl font-semibold tracking-[-0.04em] text-white">通信接口风格图谱</h2>
          <p className="mt-2 text-xs leading-6 text-slate-600">综合路径结构、调用协议、处理器命名与组件上下文，将接口归纳为 {categories.length} 类。</p>
          <div className="mx-auto mt-8 grid h-44 w-44 place-items-center rounded-full p-[18px] shadow-[0_0_60px_rgba(184,243,106,.08)]" style={{ background: gradient }}>
            <div className="grid h-full w-full place-items-center rounded-full border border-white/[0.08] bg-[#0d141d] text-center"><div><strong className="block font-mono text-3xl text-white">{total}</strong><span className="text-[9px] uppercase tracking-[0.16em] text-slate-600">classified interfaces</span></div></div>
          </div>
          <div className="mt-7 flex flex-wrap gap-x-4 gap-y-2">{categories.map((item) => <span key={item.key} className="flex items-center gap-1.5 text-[9px] text-slate-500"><i className="h-1.5 w-1.5 rounded-full" style={{ background: categoryColors[item.key] }} />{item.label}</span>)}</div>
        </article>
        <div className="grid gap-3 md:grid-cols-2 2xl:grid-cols-3">{categories.map((item) => (
          <button type="button" key={item.key} onClick={() => onSelect(item.key)} className="group relative overflow-hidden rounded-[22px] border border-white/[0.075] bg-[#0e141d]/80 p-5 text-left transition duration-300 hover:-translate-y-0.5 hover:border-white/[0.15] hover:shadow-lift">
            <span className="absolute inset-x-0 top-0 h-px opacity-60" style={{ background: `linear-gradient(90deg,transparent,${categoryColors[item.key]},transparent)` }} />
            <div className="flex items-start justify-between"><div className="grid h-10 w-10 place-items-center rounded-xl border border-white/[0.07] bg-white/[0.03]" style={{ color: categoryColors[item.key] }}><Layers3 size={17} /></div><span className="font-mono text-[10px] text-slate-700">{total ? (item.interface_count / total * 100).toFixed(1) : 0}%</span></div>
            <h3 className="mt-4 text-sm font-semibold text-white">{item.label}</h3><p className="mt-2 min-h-10 text-[10px] leading-5 text-slate-600">{item.description}</p>
            <div className="mt-4 grid grid-cols-3 gap-2 border-y border-white/[0.055] py-3 text-center"><MiniStat label="接口" value={item.interface_count} /><MiniStat label="漏洞" value={item.vulnerability_count} /><MiniStat label="固件" value={item.firmware_count} /></div>
            <p className="mt-3 text-[10px] font-medium text-slate-400">{item.vulnerability_count} 个关联漏洞</p>
            <div className="mt-2 space-y-1.5">{item.top_interfaces.slice(0, 3).map((entry) => <div key={entry.value} className="flex items-center justify-between gap-2"><code className="truncate text-[9px] text-slate-600">{entry.value}</code><span className="font-mono text-[8px] text-slate-750">{entry.value_count}</span></div>)}</div>
            <div className="mt-4 flex items-center gap-1 text-[9px] text-signal opacity-0 transition group-hover:opacity-100">展开关联图谱 <ArrowRight size={11} /></div>
          </button>
        ))}</div>
      </div>
    </>
  )
}

function CategoryDrawer({ category, page, loading, query, subtype, onQuery, onSubtype, onPage, onSelectInterface, onClose, shifted = false }: {
  category: string
  page: SemanticExplorePage<SemanticCatalogItem> | null
  loading: boolean
  query: string
  subtype: string
  onQuery: (value: string) => void
  onSubtype: (value: string) => void
  onPage: (page: number) => void
  onSelectInterface: (value: string) => void
  onClose: () => void
  shifted?: boolean
}) {
  const profile = (page?.selection || {}) as unknown as SemanticCategoryProfile
  const maxVendor = Math.max(1, ...(profile.top_vendors || []).map((item) => item.vulnerability_count))
  return (
    <div className="fixed inset-0 z-[60] bg-black/65 backdrop-blur-sm" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <aside role="dialog" aria-label={`${profile.label || category} 类别详情`} className={`absolute inset-y-0 right-0 w-full max-w-[1120px] overflow-y-auto border-l border-white/[0.09] bg-[#0b1119]/98 shadow-2xl transition-[right] duration-300 ${shifted ? 'investigation-shifted' : ''}`}>
        <header className="sticky top-0 z-20 border-b border-white/[0.07] bg-[#0b1119]/92 px-6 py-5 backdrop-blur-xl">
          <div className="flex items-start justify-between gap-4">
            <div><div className="eyebrow"><Sparkles size={13} /> Category intelligence</div><h2 className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-white">{profile.label || category}</h2><p className="mt-1 max-w-2xl text-[11px] leading-5 text-slate-600">{profile.description || '正在构建接口类别画像…'}</p></div>
            <button type="button" onClick={onClose} aria-label="关闭类别详情" className="grid h-9 w-9 place-items-center rounded-xl border border-white/[0.08] text-slate-500 transition hover:text-white"><X size={16} /></button>
          </div>
          <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4"><MiniStatCard label="关联接口" value={subtype ? profile.scope_interface_count : (profile.interface_count || page?.total || 0)} /><MiniStatCard label="关联漏洞" value={subtype ? profile.scope_vulnerability_count : (profile.vulnerability_count || 0)} /><MiniStatCard label="厂商" value={subtype ? profile.scope_vendor_count : (profile.vendor_count || 0)} /><MiniStatCard label="固件型号" value={subtype ? profile.scope_model_count : (profile.firmware_count || 0)} /></div>
        </header>
        <div className="space-y-5 p-6">
          {loading && !page ? <div className="grid min-h-80 place-items-center"><LoaderCircle className="animate-spin text-signal" /></div> : (
            <>
              <div className="grid gap-4 lg:grid-cols-2">
                <section className="rounded-2xl border border-white/[0.07] bg-white/[0.022] p-4">
                  <div className="eyebrow"><Layers3 size={12} /> Backend architecture styles</div>
                  <p className="mt-2 text-[9px] leading-4 text-slate-650">按路径语法、命名空间和分发形态推断通信结构；用于发现可能同源的后端控制面，不等同于已确认组件。</p>
                  <div className="mt-3 grid gap-2 sm:grid-cols-2">{(profile.subtypes || []).map((item) => (
                    <button key={item.key} type="button" onClick={() => onSubtype(subtype === item.key ? '' : item.key)} className={`rounded-xl border p-3 text-left transition ${subtype === item.key ? 'border-signal/35 bg-signal/[0.07]' : 'border-white/[0.06] bg-black/10 hover:border-white/[0.13]'}`}>
                      <div className="flex items-center justify-between"><strong className="text-[11px] text-slate-200">{item.label}</strong><span className="font-mono text-[9px] text-signal">{item.interface_count}</span></div>
                      <p className="mt-1.5 line-clamp-2 text-[9px] leading-4 text-slate-650">{item.description}</p>
                      <div className="mt-2 flex flex-wrap gap-1">{(item.examples || []).slice(0, 2).map((example) => <code key={example.value} title={example.value} className="max-w-full truncate rounded bg-black/25 px-1.5 py-1 text-[8px] text-cyan/80">{example.value}</code>)}</div>
                      <span className="mt-2 block text-[8px] text-slate-700">{item.vulnerability_count} 漏洞 · {item.vendor_count} 厂商 · {item.model_count} 型号</span>
                    </button>
                  ))}</div>
                </section>
                <section className="rounded-2xl border border-white/[0.07] bg-white/[0.022] p-4">
                  <div className="eyebrow"><BarChart3 size={12} /> {profile.active_subtype ? `${profile.active_subtype.label} · Vendor distribution` : 'Vendor distribution'}</div>
                  <div className="mt-4 space-y-3">{(profile.top_vendors || []).slice(0, 8).map((item) => (
                    <div key={item.vendor}><div className="mb-1.5 flex items-center justify-between text-[10px]"><span className="text-slate-400">{item.vendor}</span><span className="font-mono text-slate-600">{item.vulnerability_count} 漏洞 · {item.model_count} 型号</span></div><div className="h-1.5 overflow-hidden rounded-full bg-white/[0.05]"><i className="block h-full rounded-full bg-gradient-to-r from-cyan/50 to-signal" style={{ width: `${item.vulnerability_count / maxVendor * 100}%` }} /></div></div>
                  ))}</div>
                </section>
              </div>
              <section className="rounded-2xl border border-white/[0.07] bg-white/[0.022] p-4">
                <div className="eyebrow"><CircuitBoard size={12} /> {profile.active_subtype ? `${profile.active_subtype.label} · Firmware families` : 'Standard firmware models'}</div>
                <p className="mt-2 text-[9px] text-slate-650">{profile.active_subtype ? '以下厂商与型号均出现过该通信架构，可作为后端结构同族分析的候选集合。' : '选择一种后端架构风格，即可收敛到可能共享通信结构的厂商与固件型号。'}</p>
                <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">{(profile.top_models || []).map((model) => (
                  <article key={model.key} className="rounded-xl border border-white/[0.06] bg-black/10 p-3"><strong className="block truncate text-[11px] text-slate-200" title={model.label}>{model.label}</strong><div className="mt-2 flex items-center justify-between gap-2"><span className="font-mono text-[9px] text-cyan">{model.version_summary}</span><span className={`rounded px-1.5 py-0.5 text-[8px] ${model.alignment === 'aligned' ? 'bg-signal/10 text-signal' : 'bg-amber-400/10 text-amber-300'}`}>{model.alignment === 'aligned' ? '描述/CPE 一致' : model.source === 'description' ? '描述优先' : 'CPE 补全'}</span></div><span className="mt-2 block text-[8px] text-slate-700">{model.vulnerability_count || 0} 个漏洞</span></article>
                ))}</div>
              </section>
              <section className="overflow-hidden rounded-2xl border border-white/[0.07] bg-white/[0.022]">
                <div className="flex flex-col gap-3 border-b border-white/[0.06] p-4 sm:flex-row sm:items-center sm:justify-between"><div><h3 className="text-sm font-semibold text-white">类别关联接口</h3><p className="mt-1 text-[9px] text-slate-650">点击接口继续查看关联漏洞与完整漏洞档案。</p></div><label className="search-field w-full sm:w-[300px]"><Search size={14} /><input value={query} onChange={(event) => onQuery(event.target.value)} placeholder="搜索该类别下的接口…" /></label></div>
                <div className="divide-y divide-white/[0.055]">{page?.items.map((item) => (
                  <button key={item.value} type="button" onClick={() => onSelectInterface(item.value)} className="group grid w-full grid-cols-[minmax(0,1fr)_105px] items-center gap-3 px-4 py-3 text-left transition hover:bg-white/[0.035] sm:grid-cols-[minmax(0,1fr)_160px_120px_100px]">
                    <div className="min-w-0"><code className="block truncate text-[11px] font-semibold text-slate-200 group-hover:text-signal">{item.value}</code><span className="mt-1 block text-[9px] text-slate-650">{[item.method, item.protocol, item.component].filter(Boolean).join(' · ') || '管理路由'}</span></div>
                    <span className="rounded-lg border border-white/[0.07] px-2 py-1 text-[9px] text-cyan">{item.subtype_label || item.subtype || '未定型结构'}</span>
                    <span className="hidden text-[9px] text-slate-600 sm:block">{item.vendor_count} 家厂商</span>
                    <span className="flex items-center justify-end gap-2 font-mono text-[10px] text-white">{item.vulnerability_count}<ArrowRight size={12} className="text-slate-700 group-hover:text-signal" /></span>
                  </button>
                ))}</div>
                {page && <PaginationControls page={page.page} pages={page.pages} total={page.total} hasPrevious={page.has_previous} hasNext={page.has_next} onPage={onPage} />}
              </section>
            </>
          )}
        </div>
      </aside>
    </div>
  )
}

function AssociationDrawer({ kind, value, page, loading, onClose, onPage, parentLabel }: { kind: SemanticExploreKind; value: string; page: SemanticExplorePage<SemanticAssociation> | null; loading: boolean; onClose: () => void; onPage: (page: number) => void; parentLabel?: string }) {
  const [expanded, setExpanded] = useState<Vulnerability | null>(null)
  const [expandedLoading, setExpandedLoading] = useState<string | null>(null)
  const selection = page?.selection ?? {}
  const label = String(selection.label || selection.value || value)
  const openVulnerability = async (identifier: string) => {
    setExpandedLoading(identifier)
    try { setExpanded(await intelligenceApi.vulnerability(identifier)) }
    finally { setExpandedLoading(null) }
  }
  return (
    <div className="fixed inset-0 z-[70] bg-black/65 backdrop-blur-sm" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <aside role="dialog" aria-label={`${label} 关联详情`} className={`absolute inset-y-0 right-0 w-full max-w-[760px] overflow-y-auto border-l border-white/[0.09] bg-[#0b1119]/98 shadow-2xl transition-[right] duration-300 ${expanded ? 'investigation-shifted' : ''}`}>
        <header className="sticky top-0 z-10 border-b border-white/[0.07] bg-[#0b1119]/90 px-6 py-5 backdrop-blur-xl">
          <div className="flex items-start justify-between gap-4"><div>{parentLabel && <button type="button" onClick={onClose} className="mb-3 flex items-center gap-2 text-[10px] text-signal transition hover:text-white"><ArrowLeft size={12} /> 返回 {parentLabel}</button>}<div className="eyebrow"><Network size={13} /> Association drilldown</div><h2 className="mt-2 break-all font-mono text-xl font-semibold text-white">{label}</h2><p className="mt-2 text-[11px] text-slate-600">{kind === 'category' ? String(selection.description || '接口风格关联') : [selection.method, selection.protocol, selection.category].filter(Boolean).join(' · ')}</p></div><button type="button" onClick={onClose} aria-label={parentLabel ? '返回类别详情' : '关闭关联详情'} className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-white/[0.08] text-slate-500 transition hover:text-white">{parentLabel ? <ArrowLeft size={16} /> : <X size={16} />}</button></div>
          <div className="mt-4 flex gap-2"><span className="rounded-lg bg-signal/[0.08] px-2.5 py-1 text-[9px] text-signal">{page?.total ?? 0} 漏洞</span>{selection.vendor_count != null && <span className="rounded-lg bg-cyan/[0.08] px-2.5 py-1 text-[9px] text-cyan">{String(selection.vendor_count)} 厂商</span>}</div>
        </header>
        <div className="space-y-3 p-6">{loading && !page ? <div className="grid min-h-64 place-items-center"><LoaderCircle className="animate-spin text-signal" /></div> : page?.items.map((item) => (
          <button type="button" key={item.identifier} onClick={() => void openVulnerability(item.identifier)} className="group block w-full rounded-2xl border border-white/[0.07] bg-white/[0.025] p-5 text-left transition hover:border-signal/20 hover:bg-white/[0.035]">
            <div className="flex flex-wrap items-center gap-2"><code className="text-[10px] font-semibold text-signal">{item.identifier}</code>{item.severity && <span className={`rounded px-1.5 py-0.5 text-[8px] font-bold ring-1 ring-inset ${severityTone(item.severity)}`}>{item.cvss_score?.toFixed(1) ?? item.severity}</span>}<span className="ml-auto text-[9px] text-slate-700">{formatRelativeTime(item.published_at || item.modified_at)}</span></div>
            <h3 className="mt-3 text-sm font-semibold leading-6 text-white">{item.title}</h3>
            <div className="mt-3 grid gap-2 sm:grid-cols-2"><Info icon={Boxes} label="厂商" value={item.vendor || '未知厂商'} /><Info icon={CircuitBoard} label="标准固件型号" value={item.firmware_model?.label || item.product || '未知固件'} /></div>
            {item.semantic_evidence && <div className="mt-3 rounded-xl border border-signal/10 bg-signal/[0.035] px-3 py-2.5"><div className="flex items-center gap-1.5 text-[8px] uppercase tracking-wider text-signal/70"><ShieldAlert size={11} /> 原文证据</div><p className="mt-1.5 text-[10px] leading-5 text-slate-500">{item.semantic_evidence}</p></div>}
            <div className="mt-3 flex items-center justify-between border-t border-white/[0.05] pt-3"><span className="text-[9px] text-slate-650">版本边界：<strong className="font-mono font-medium text-cyan">{item.firmware_model?.version_summary || '版本未明确'}</strong></span><span className="flex items-center gap-1 text-[9px] text-signal">{expandedLoading === item.identifier ? <LoaderCircle size={11} className="animate-spin" /> : <>查看完整漏洞档案 <ArrowRight size={11} /></>}</span></div>
          </button>
        ))}</div>
        {page && <PaginationControls page={page.page} pages={page.pages} total={page.total} hasPrevious={page.has_previous} hasNext={page.has_next} onPage={onPage} />}
      </aside>
      <VulnerabilityDetail vulnerability={expanded} onClose={() => setExpanded(null)} layerClassName="z-[90]" parentLabel={label} />
    </div>
  )
}

function StyleBadge({ category }: { category: string }) {
  const labels: Record<string, string> = { form_handler: 'Form handler', cgi_gateway: 'CGI gateway', hnap_soap: 'HNAP / SOAP', resource_api: 'Resource API', web_action: 'Web action', rpc_command: 'RPC / command', management_route: 'Management' }
  return <span className="hidden w-fit rounded-lg border border-white/[0.07] bg-white/[0.025] px-2 py-1 text-[9px] text-slate-500 sm:block">{labels[category] || category}</span>
}
function MiniStat({ label, value }: { label: string; value: number }) { return <div><strong className="block font-mono text-xs text-slate-300">{value}</strong><span className="mt-1 block text-[8px] text-slate-700">{label}</span></div> }
function MiniStatCard({ label, value }: { label: string; value: number }) { return <div className="rounded-xl border border-white/[0.06] bg-white/[0.025] px-3 py-2"><strong className="font-mono text-sm text-white">{value}</strong><span className="ml-2 text-[8px] uppercase tracking-wider text-slate-650">{label}</span></div> }
function Info({ icon: Icon, label, value }: { icon: typeof Boxes; label: string; value: string }) { return <div className="rounded-xl border border-white/[0.055] bg-black/10 px-3 py-2"><span className="flex items-center gap-1.5 text-[8px] uppercase tracking-wider text-slate-700"><Icon size={10} />{label}</span><strong className="mt-1 block truncate text-[11px] font-medium text-slate-300" title={value}>{value}</strong></div> }
