import { Activity, Braces, ChevronRight, CircleDot, Database, FileCode2, Search, Waypoints } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { intelligenceApi } from '../api/client'
import { useDebouncedValue } from '../hooks/useDebouncedValue'
import type { MappingCandidate, MappingCandidateDetail, MappingCatalogSummary } from '../types'

const kinds = [
  ['', '全部能力'], ['request_interface', '请求接口'], ['web_configuration', 'Web 配置'],
  ['script_route', '脚本路由'], ['native_hint', '原生提示'],
  ['native_route_binding', 'Native 绑定'], ['native_handler', 'Native Handler'],
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
  const debouncedQuery = useDebouncedValue(query, 180)

  useEffect(() => {
    const controller = new AbortController()
    void intelligenceApi.mappingCatalogs(controller.signal).then((page) => {
      setCatalogs(page.items)
      setCatalogId((current) => current || page.items[0]?.catalog_id || '')
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
        {activeCatalog && <StatusPill catalog={activeCatalog} />}
      </header>

      {error && <div role="alert" className="mb-4 rounded-xl border border-ember/20 bg-ember/[0.06] px-4 py-3 text-xs text-ember">{error}</div>}

      {!loading && catalogs.length === 0 ? <EmptyCatalog /> : (
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

function StatusPill({ catalog }: { catalog: MappingCatalogSummary }) {
  return <div className="flex items-center gap-3 rounded-xl border border-white/[0.07] bg-white/[0.025] px-4 py-3"><Activity size={16} className="text-signal" /><div><div className="text-[9px] uppercase tracking-[0.16em] text-slate-600">Latest coverage</div><div className="mt-1 text-xs text-slate-300">{catalog.coverage_status} · {catalog.candidate_count} candidates</div></div></div>
}

function CandidateRow({ candidate, active, onClick }: { candidate: MappingCandidate; active: boolean; onClick: () => void }) {
  return <button type="button" onClick={onClick} aria-label={`查看候选 ${candidate.canonical_identity}`} className={`group mb-1 flex w-full items-center gap-3 rounded-xl border px-3 py-3 text-left transition ${active ? 'border-signal/20 bg-signal/[0.06]' : 'border-transparent hover:border-white/[0.06] hover:bg-white/[0.025]'}`}>
    <div className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-cyan/[0.07] text-cyan"><Braces size={15} /></div><div className="min-w-0 flex-1"><div className="truncate font-mono text-xs text-slate-200">{candidate.canonical_identity}</div><div className="mt-1 flex gap-2 text-[9px] uppercase tracking-[0.09em] text-slate-600"><span>{candidate.candidate_kind.replaceAll('_', ' ')}</span><span>{candidate.parameter_count} params</span><span>{candidate.association_count} links</span></div></div><ChevronRight size={14} className="text-slate-700 transition group-hover:translate-x-0.5 group-hover:text-signal" />
  </button>
}

function CandidateEvidence({ detail }: { detail: MappingCandidateDetail }) {
  const item = detail.candidate
  const title = item.candidate_kind === 'candidate_association'
    ? '跨层候选关联'
    : item.canonical_identity
  return <article className="detail-enter max-h-[640px] overflow-y-auto p-5 sm:p-6">
    <div className="eyebrow"><FileCode2 size={12} /> Evidence detail</div><h2 className="mt-3 break-all font-mono text-lg font-semibold text-white">{title}</h2><p className="mt-2 break-all text-xs text-slate-600">{item.source_path} · {item.source_construct}</p>
    {item.candidate_kind === 'candidate_association' && <p className="mt-2 break-all font-mono text-[9px] leading-4 text-slate-700">{item.canonical_identity}</p>}
    <div className="mt-5 grid grid-cols-3 gap-2">{[['参数', detail.parameters.length], ['关联', detail.associations.length + detail.related_candidates.length], ['未决', detail.open_obligations.length]].map(([label, value]) => <div key={label} className="rounded-xl border border-white/[0.06] bg-black/20 p-3"><div className="text-[9px] text-slate-600">{label}</div><div className="mt-1 text-lg font-semibold text-slate-200">{value}</div></div>)}</div>
    <EvidenceSection title="参数与操作选择器">{detail.parameters.length ? detail.parameters.map((parameter) => <div key={parameter.parameter_id} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3"><div className="font-mono text-xs text-cyan">{parameter.name}</div><div className="mt-1 text-[10px] text-slate-600">{parameter.namespace}{parameter.is_operation_selector ? ' · operation selector' : ''}{parameter.literal_value ? ` · ${parameter.literal_value}` : ''}</div></div>) : <Muted />}</EvidenceSection>
    <EvidenceSection title="跨层关联">{detail.associations.length ? detail.associations.map((association) => <div key={association.association_id} className="rounded-lg border border-signal/10 bg-signal/[0.035] p-3 text-xs text-slate-400"><span className="text-signal">{association.match_basis}</span><div className="mt-1 break-all font-mono text-[9px] text-slate-600">{association.native_hint_id}</div></div>) : <Muted />}</EvidenceSection>
    <EvidenceSection title="已验证 Native 绑定">{detail.related_candidates.length ? detail.related_candidates.map((related) => <div key={related.candidate_id} className="rounded-lg border border-cyan/15 bg-cyan/[0.035] p-3"><div className="flex items-center justify-between gap-3"><span className="font-mono text-xs text-cyan">{related.canonical_identity}</span><span className="text-[9px] uppercase tracking-[0.1em] text-signal">{related.claim_status}</span></div><div className="mt-1 break-all text-[9px] text-slate-600">{related.candidate_kind.replaceAll('_', ' ')} · {related.source_construct}</div></div>) : <Muted />}</EvidenceSection>
    <EvidenceSection title="原始证据位置">{detail.evidence_atoms.map((atom) => <div key={atom.evidence_id} className="rounded-lg border border-white/[0.06] p-3"><div className="text-[10px] text-slate-400">{atom.capability}</div><div className="mt-1 break-all font-mono text-[9px] leading-5 text-slate-600">{atom.source_span.artifact_path} · {atom.source_span.locator}</div></div>)}</EvidenceSection>
  </article>
}

function EvidenceSection({ title, children }: { title: string; children: React.ReactNode }) { return <section className="mt-6"><h3 className="mb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">{title}</h3><div className="space-y-2">{children}</div></section> }
function Muted() { return <div className="rounded-lg border border-dashed border-white/[0.06] p-3 text-[10px] text-slate-700">当前目录未发布该类事实</div> }
function EmptyCatalog() { return <div className="rounded-2xl border border-dashed border-white/[0.08] bg-white/[0.015] p-14 text-center"><Database className="mx-auto text-slate-700" /><h2 className="mt-4 text-sm text-slate-300">尚未发布测绘目录</h2><p className="mt-2 text-xs text-slate-600">完成 Producer Batch、关联和义务调度后，通过持久化接口发布目录。</p></div> }
