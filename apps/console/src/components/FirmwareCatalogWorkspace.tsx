import {
  Archive,
  Boxes,
  Building2,
  ChevronRight,
  Database,
  Download,
  ExternalLink,
  FileArchive,
  FlaskConical,
  GitFork,
  Link2,
  LoaderCircle,
  PackageSearch,
  Search,
  ShieldCheck,
  X,
} from 'lucide-react'
import { useEffect, useMemo, useState, type ReactNode } from 'react'

import { intelligenceApi } from '../api/client'
import { useDebouncedValue } from '../hooks/useDebouncedValue'
import type {
  FirmwareCandidate,
  FirmwareCandidateDetail,
  FirmwareCandidatePage,
  FirmwareCatalogOverview,
  FirmwareSource,
} from '../types'
import { PaginationControls } from './PaginationControls'

interface FirmwareCatalogWorkspaceProps {
  initialQuery?: string
  onOpenVulnerability: (identifier: string) => void
}

const emptyPage: FirmwareCandidatePage = {
  items: [], total: 0, limit: 30, offset: 0, page: 1, pages: 0,
  has_previous: false, has_next: false,
}

export function FirmwareCatalogWorkspace({
  initialQuery = '', onOpenVulnerability,
}: FirmwareCatalogWorkspaceProps) {
  const [overview, setOverview] = useState<FirmwareCatalogOverview | null>(null)
  const [sources, setSources] = useState<FirmwareSource[]>([])
  const [page, setPage] = useState(emptyPage)
  const [query, setQuery] = useState(initialQuery)
  const [vendor, setVendor] = useState('')
  const [source, setSource] = useState('')
  const [linkedOnly, setLinkedOnly] = useState(false)
  const [currentPage, setCurrentPage] = useState(1)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [detail, setDetail] = useState<FirmwareCandidateDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [filtering, setFiltering] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const stableQuery = useDebouncedValue(query, 280)

  useEffect(() => {
    setQuery(initialQuery)
  }, [initialQuery])

  useEffect(() => {
    let active = true
    Promise.all([intelligenceApi.firmwareOverview(), intelligenceApi.firmwareSources()])
      .then(([nextOverview, nextSources]) => {
        if (!active) return
        setOverview(nextOverview)
        setSources(nextSources.items)
      })
      .catch((caught) => active && setError(errorMessage(caught)))
    return () => { active = false }
  }, [])

  useEffect(() => { setCurrentPage(1) }, [stableQuery, vendor, source, linkedOnly])

  useEffect(() => {
    const controller = new AbortController()
    setFiltering(true)
    intelligenceApi.firmwareCandidates(
      { query: stableQuery, vendor, source, hasVulnerability: linkedOnly },
      currentPage,
      controller.signal,
    ).then((nextPage) => {
      setPage(nextPage)
      setError(null)
    }).catch((caught) => {
      if (!controller.signal.aborted) setError(errorMessage(caught))
    }).finally(() => {
      if (!controller.signal.aborted) {
        setFiltering(false)
        setLoading(false)
      }
    })
    return () => controller.abort()
  }, [stableQuery, vendor, source, linkedOnly, currentPage])

  useEffect(() => {
    if (!selectedId) { setDetail(null); return }
    const controller = new AbortController()
    intelligenceApi.firmwareCandidate(selectedId, controller.signal)
      .then(setDetail)
      .catch((caught) => !controller.signal.aborted && setError(errorMessage(caught)))
    return () => controller.abort()
  }, [selectedId])

  const activeFilters = [stableQuery, vendor, source, linkedOnly ? 'linked' : ''].filter(Boolean).length
  const vendors = overview?.vendors ?? []
  const sourceById = useMemo(
    () => new Map(sources.map((item) => [item.source_id, item])), [sources],
  )
  const featuredSources = useMemo(
    () => [...sources].sort((left, right) => (
      right.candidate_count - left.candidate_count
      || right.vulnerability_count - left.vulnerability_count
      || left.name.localeCompare(right.name)
    )).slice(0, 12),
    [sources],
  )

  const clearFilters = () => {
    setQuery(''); setVendor(''); setSource(''); setLinkedOnly(false)
  }

  return (
    <div>
      <header className="mb-7 flex flex-col gap-5 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <div className="eyebrow"><PackageSearch size={13} /> Firmware evidence / Sample discovery</div>
          <h1 className="mt-3 text-[30px] font-semibold leading-none tracking-[-0.045em] text-white sm:text-[38px]">
            固件样本目录
          </h1>
          <p className="mt-3 max-w-3xl text-xs leading-6 text-slate-500 sm:text-sm">
            聚合公开 benchmark、厂商下载中心与研究证据。当前只记录候选地址，未下载的文件不会被标记为已验证制品。
          </p>
        </div>
        <div className="flex items-center gap-2 rounded-xl border border-signal/15 bg-signal/[0.055] px-3 py-2 text-[10px] text-signal">
          <ShieldCheck size={14} /> Metadata only · 未执行固件下载
        </div>
      </header>

      {error && <div role="alert" className="mb-5 rounded-xl border border-ember/15 bg-ember/[0.055] px-4 py-3 text-xs text-ember">{error}</div>}

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <Metric icon={<Database size={16} />} label="样本候选" value={overview?.counts.candidate_count ?? 0} tone="signal" />
        <Metric icon={<Link2 size={16} />} label="漏洞线索" value={overview?.counts.vulnerability_lead_count ?? 0} tone="ember" />
        <Metric icon={<FlaskConical size={16} />} label="已关联候选" value={overview?.counts.linked_candidate_count ?? 0} tone="violet" />
        <Metric icon={<Building2 size={16} />} label="官方来源" value={overview?.counts.official_source_count ?? 0} tone="cyan" />
        <Metric icon={<Archive size={16} />} label="来源总数" value={overview?.counts.source_count ?? 0} tone="slate" />
      </section>

      <section className="mt-4 overflow-hidden rounded-2xl border border-white/[0.07] bg-white/[0.02]">
        <div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-3">
          <div><div className="eyebrow">Source constellation</div><h2 className="mt-1 text-sm font-semibold text-white">固件来源星图</h2></div>
          <span className="text-[9px] text-slate-700">点击来源过滤候选 · 官方门户即使暂无具体样本也保留</span>
        </div>
        <div className="grid gap-px bg-white/[0.05] sm:grid-cols-2 xl:grid-cols-4">
          {featuredSources.map((item) => (
            <button key={item.source_id} type="button" onClick={() => setSource(source === item.source_id ? '' : item.source_id)}
              className={`group min-h-[92px] bg-[#0b1018] p-4 text-left transition hover:bg-white/[0.04] ${source === item.source_id ? 'ring-1 ring-inset ring-signal/40' : ''}`}>
              <div className="flex items-center justify-between gap-3">
                <SourceIcon type={item.source_type} />
                <span className={`rounded px-1.5 py-0.5 text-[8px] uppercase tracking-wider ${trustTone(item.trust_level)}`}>{trustLabel(item.trust_level)}</span>
              </div>
              <div className="mt-3 truncate text-[11px] font-medium text-slate-300 group-hover:text-white">{item.name}</div>
              <div className="mt-1 flex gap-3 text-[9px] text-slate-700"><span>{item.candidate_count} 候选</span><span>{item.vulnerability_count} 漏洞</span></div>
            </button>
          ))}
        </div>
      </section>

      <section className="relative mt-4 overflow-hidden rounded-2xl border border-white/[0.07] bg-[#0b1018]/90">
        {filtering && <div className="absolute inset-x-0 top-0 h-px overflow-hidden"><span className="filter-progress block h-full w-1/3 bg-signal" /></div>}
        <div className="flex flex-col gap-3 border-b border-white/[0.07] p-4 xl:flex-row xl:items-center">
          <label className="search-field flex-1" aria-label="搜索固件样本">
            <Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索 CVE、厂商、型号、版本或文件名…" />
          </label>
          <label className="select-field"><span className="sr-only">厂商</span><select value={vendor} onChange={(event) => setVendor(event.target.value)}><option value="">全部厂商</option>{vendors.map((item) => <option key={item.label} value={item.label}>{item.label} · {item.value}</option>)}</select></label>
          <label className="select-field"><span className="sr-only">来源</span><select value={source} onChange={(event) => setSource(event.target.value)}><option value="">全部来源</option>{sources.map((item) => <option key={item.source_id} value={item.source_id}>{item.name}</option>)}</select></label>
          <button type="button" onClick={() => setLinkedOnly((value) => !value)} className={`filter-button ${linkedOnly ? 'filter-button-exploit' : ''}`}><Link2 size={14} /> 有漏洞线索</button>
          {activeFilters > 0 && <button type="button" onClick={clearFilters} className="filter-button"><X size={13} /> 清除 {activeFilters}</button>}
        </div>

        <div className="grid grid-cols-[132px_minmax(0,1.3fr)_minmax(180px,.8fr)_94px] border-b border-white/[0.06] px-4 py-2.5 text-[8px] font-semibold uppercase tracking-[0.18em] text-slate-700">
          <span>Candidate</span><span>Firmware identity</span><span>Evidence route</span><span className="text-right">Links</span>
        </div>
        <div className="divide-y divide-white/[0.055]">
          {page.items.map((item) => <CandidateRow key={item.candidate_id} item={item} onSelect={() => setSelectedId(item.candidate_id)} />)}
          {!loading && page.items.length === 0 && <div className="py-16 text-center"><FileArchive size={24} className="mx-auto text-slate-800" /><p className="mt-3 text-xs text-slate-600">当前条件下没有固件样本候选</p></div>}
          {loading && <div className="flex items-center justify-center gap-2 py-16 text-xs text-slate-600"><LoaderCircle size={15} className="animate-spin" />正在读取固件目录…</div>}
        </div>
        <PaginationControls
          page={page.page}
          pages={page.pages}
          total={page.total}
          hasPrevious={page.has_previous}
          hasNext={page.has_next}
          onPage={setCurrentPage}
          disabled={filtering}
          detail="每页 30 条"
        />
      </section>

      {detail && <CandidateDrawer detail={detail} source={sourceById.get(detail.source_id)} onClose={() => setSelectedId(null)} onOpenVulnerability={onOpenVulnerability} />}
    </div>
  )
}

function CandidateRow({ item, onSelect }: { item: FirmwareCandidate; onSelect: () => void }) {
  return <button type="button" onClick={onSelect} className="grid w-full grid-cols-[132px_minmax(0,1.3fr)_minmax(180px,.8fr)_94px] items-center gap-4 px-4 py-4 text-left transition hover:bg-white/[0.025]">
    <div><div className="font-mono text-[10px] font-semibold text-signal">{item.external_id || item.candidate_id}</div><div className="mt-1 text-[9px] text-slate-700">{item.url_status === 'listed' ? '地址已收录' : item.url_status}</div></div>
    <div className="min-w-0"><div className="truncate text-xs font-medium text-slate-200">{item.vendor} · {item.model}</div><div className="mt-1 truncate font-mono text-[9px] text-slate-600">{item.filename}</div></div>
    <div className="min-w-0"><div className="flex items-center gap-2 text-[10px] text-slate-400"><SourceIcon type={item.source_type} /> <span className="truncate">{item.source_name}</span></div><div className="mt-1 text-[8px] uppercase tracking-wider text-slate-700">{trustLabel(item.trust_level)} · {item.download_kind === 'direct' ? 'direct URL' : 'portal'}</div></div>
    <div className="flex items-center justify-end gap-2"><span className={`rounded-lg px-2 py-1 font-mono text-[10px] ${item.vulnerability_count ? 'bg-ember/10 text-ember' : 'bg-white/[0.04] text-slate-600'}`}>{item.vulnerability_count} CVE</span><ChevronRight size={14} className="text-slate-700" /></div>
  </button>
}

function CandidateDrawer({ detail, source, onClose, onOpenVulnerability }: { detail: FirmwareCandidateDetail; source?: FirmwareSource; onClose: () => void; onOpenVulnerability: (identifier: string) => void }) {
  return <div className="fixed inset-0 z-[70] flex justify-end bg-black/60 backdrop-blur-sm" onMouseDown={onClose}><aside role="dialog" aria-modal="true" aria-label={`固件样本 ${detail.model}`} onMouseDown={(event) => event.stopPropagation()} className="detail-enter h-full w-full max-w-[620px] overflow-y-auto border-l border-white/10 bg-[#0b1018]/98 p-6 shadow-2xl sm:p-8">
    <div className="flex items-start justify-between"><div><div className="eyebrow"><FileArchive size={13} /> Sample candidate evidence</div><div className="mt-3 font-mono text-xs text-signal">{detail.external_id}</div></div><button type="button" onClick={onClose} className="icon-button" aria-label="关闭固件详情"><X size={18} /></button></div>
    <h2 className="mt-5 text-2xl font-semibold tracking-[-0.035em] text-white">{detail.vendor} {detail.model}</h2>
    <p className="mt-2 break-all font-mono text-[11px] leading-5 text-slate-500">{detail.filename}</p>
    <div className="mt-6 grid grid-cols-3 gap-2"><MiniMetric label="来源可信度" value={trustLabel(detail.trust_level)} /><MiniMetric label="漏洞线索" value={String(detail.vulnerability_count)} /><MiniMetric label="下载状态" value="未下载" /></div>
    <section className="mt-7 rounded-2xl border border-signal/15 bg-signal/[0.045] p-4"><div className="flex items-center gap-2 text-xs font-semibold text-signal"><Download size={15} />候选下载地址</div><a href={detail.download_url} target="_blank" rel="noreferrer" className="mt-3 block break-all rounded-xl border border-white/[0.07] bg-black/20 p-3 font-mono text-[10px] leading-5 text-cyan hover:border-cyan/25">{detail.download_url}</a><p className="mt-3 text-[10px] leading-5 text-slate-600">该地址来自公开元数据，FirmAtlas 尚未下载、计算哈希或验证内容真实性。</p></section>
    <section className="mt-7"><h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500">来源证据</h3><div className="mt-3 space-y-2"><EvidenceLink href={detail.source_page_url} label="Benchmark / 发行页面" /><EvidenceLink href={detail.evidence_url} label="目录证据" /><EvidenceLink href={detail.source_base_url} label={source?.name || detail.source_name} /></div>{detail.source_access_notes && <p className="mt-3 text-[10px] leading-5 text-slate-600">{detail.source_access_notes}</p>}</section>
    <section className="mt-7 pb-10"><div className="flex items-center justify-between"><h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500">关联漏洞线索</h3><span className="text-[9px] text-slate-700">线索 ≠ 已验证漏洞匹配</span></div><div className="mt-3 space-y-2">{detail.vulnerabilities.map((item) => <button key={item.vulnerability_identifier} type="button" onClick={() => onOpenVulnerability(item.vulnerability_identifier)} className="flex w-full items-center gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] p-3 text-left transition hover:border-ember/20 hover:bg-ember/[0.04]"><FlaskConical size={14} className="text-ember" /><div className="min-w-0 flex-1"><div className="font-mono text-[10px] font-semibold text-slate-200">{item.vulnerability_identifier}</div><div className="mt-1 truncate text-[9px] text-slate-600">{item.title || item.relationship}</div></div><span className="rounded bg-signal/[0.08] px-1.5 py-1 text-[8px] uppercase text-signal">{item.confidence}</span><ChevronRight size={13} className="text-slate-700" /></button>)}{detail.vulnerabilities.length === 0 && <p className="rounded-xl border border-dashed border-white/[0.07] py-8 text-center text-[10px] text-slate-700">暂未发现明确漏洞环境关联</p>}</div></section>
  </aside></div>
}

function Metric({ icon, label, value, tone }: { icon: ReactNode; label: string; value: number; tone: string }) { return <article className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-4"><div className="flex items-center justify-between text-[10px] text-slate-600"><span>{label}</span><span className={`tone-${tone} rounded-lg p-2`}>{icon}</span></div><strong className="mt-5 block text-2xl text-white">{value.toLocaleString()}</strong></article> }
function MiniMetric({ label, value }: { label: string; value: string }) { return <div className="rounded-xl border border-white/[0.07] bg-white/[0.025] p-3"><div className="text-[8px] uppercase tracking-wider text-slate-700">{label}</div><div className="mt-2 text-xs font-semibold text-slate-300">{value}</div></div> }
function SourceIcon({ type }: { type: string }) { return type === 'official' ? <Building2 size={14} className="text-cyan" /> : type === 'benchmark' ? <GitFork size={14} className="text-violet-300" /> : <Archive size={14} className="text-slate-500" /> }
function EvidenceLink({ href, label }: { href: string; label: string }) { return <a href={href} target="_blank" rel="noreferrer" className="flex items-center gap-2 rounded-xl border border-white/[0.06] px-3 py-2.5 text-[10px] text-slate-500 transition hover:border-white/15 hover:text-cyan"><ExternalLink size={13} /><span className="min-w-0 flex-1 truncate">{label}</span><span className="max-w-[55%] truncate font-mono text-[8px] text-slate-700">{href}</span></a> }
function trustLabel(value: string) { return value === 'primary' ? '官方' : value === 'high' ? '高可信' : value === 'medium' ? '中可信' : '待核验' }
function trustTone(value: string) { return value === 'primary' ? 'bg-cyan/[0.08] text-cyan' : value === 'high' ? 'bg-violet-400/[0.08] text-violet-300' : 'bg-white/[0.05] text-slate-500' }
function errorMessage(value: unknown) { return value instanceof Error ? value.message : '固件目录服务暂不可用' }
