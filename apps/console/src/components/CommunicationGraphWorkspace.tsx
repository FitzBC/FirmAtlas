import {
  Activity, AlertTriangle, Boxes, Braces, ChevronRight, CircleDot,
  Database, FileSearch, GitBranch, History, Layers3, Network, Search,
  ShieldQuestion,
} from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { intelligenceApi } from '../api/client'
import { useDebouncedValue } from '../hooks/useDebouncedValue'
import type {
  CommunicationGraphEdge, CommunicationGraphEvidenceAtom,
  CommunicationGraphNode, CommunicationGraphQueryResult,
  CommunicationGraphSummary, HistoricalGraphOverlayEntry,
  HistoricalGraphOverlayQueryResult,
} from '../types'

const presetLabels: Record<string, string> = {
  interface_structure: '接口结构',
  parameter_state: '参数与状态',
  communication_components: '通信组件',
  completeness: '完整性与义务',
}

const nodeTone: Record<string, string> = {
  interface: 'border-cyan/35 bg-cyan/[0.09] text-cyan',
  parameter: 'border-violet-300/25 bg-violet-300/[0.08] text-violet-200',
  runtime_principal: 'border-signal/30 bg-signal/[0.075] text-signal',
  component: 'border-signal/30 bg-signal/[0.075] text-signal',
  handler: 'border-amber-300/30 bg-amber-300/[0.08] text-amber-200',
  route_binding: 'border-amber-300/30 bg-amber-300/[0.08] text-amber-200',
  obligation: 'border-ember/35 bg-ember/[0.085] text-ember',
  feature_gate: 'border-slate-400/25 bg-slate-400/[0.07] text-slate-300',
  state: 'border-fuchsia-300/30 bg-fuchsia-300/[0.08] text-fuchsia-200',
  communication_relation: 'border-signal/30 bg-signal/[0.075] text-signal',
}

const kindRank: Record<string, number> = {
  artifact: 0, component: 0, runtime_principal: 0,
  invocation: 1, interface: 1, communication_relation: 1,
  parameter: 2, parameter_clue: 2, response_contract: 2,
  dispatch: 3, route_binding: 3, backend_binding: 3, feature_gate: 3,
  handler: 4, service_assembly: 4, protection: 4, access_grant: 4,
  state: 5,
  obligation: 5, association: 5, evidence_candidate: 5,
}

interface PositionedNode {
  node: CommunicationGraphNode
  x: number
  y: number
}

export function CommunicationGraphWorkspace() {
  const [graphs, setGraphs] = useState<CommunicationGraphSummary[]>([])
  const [graphId, setGraphId] = useState('')
  const [interfaceQuery, setInterfaceQuery] = useState('')
  const [interfaceIndex, setInterfaceIndex] = useState<CommunicationGraphQueryResult | null>(null)
  const [selectedInterface, setSelectedInterface] = useState<CommunicationGraphNode | null>(null)
  const [indexMode, setIndexMode] = useState<'interfaces' | 'history'>('interfaces')
  const [historicalOverlay, setHistoricalOverlay] = useState<HistoricalGraphOverlayQueryResult | null>(null)
  const [selectedHistory, setSelectedHistory] = useState<HistoricalGraphOverlayEntry | null>(null)
  const [overlayError, setOverlayError] = useState<string | null>(null)
  const [preset, setPreset] = useState('interface_structure')
  const [result, setResult] = useState<CommunicationGraphQueryResult | null>(null)
  const [selectedNodeId, setSelectedNodeId] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const debouncedQuery = useDebouncedValue(interfaceQuery, 180)

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    void intelligenceApi.mappingGraphs(controller.signal).then((page) => {
      setGraphs(page.items)
      setGraphId((current) => current || page.items[0]?.graph_id || '')
      setError(null)
    }).catch((caught) => {
      if (!controller.signal.aborted) {
        setError(caught instanceof Error ? caught.message : '通信图列表加载失败')
      }
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    if (!graphId) { setInterfaceIndex(null); return }
    const controller = new AbortController()
    setLoading(true)
    void intelligenceApi.mappingGraph(graphId, {
      query: debouncedQuery,
      nodeKinds: ['interface', 'state'],
      maxHops: 0,
      maxNodes: 200,
      maxEdges: 1,
    }, controller.signal).then((next) => {
      setInterfaceIndex(next)
      setSelectedInterface((current) => next.nodes.some(
        (node) => node.node_id === current?.node_id,
      ) ? current : null)
      setError(null)
    }).catch((caught) => {
      if (!controller.signal.aborted) {
        setError(caught instanceof Error ? caught.message : '接口索引加载失败')
      }
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [graphId, debouncedQuery])

  useEffect(() => {
    if (!graphId) { setHistoricalOverlay(null); return }
    const controller = new AbortController()
    void intelligenceApi.mappingHistoricalOverlay(graphId, controller.signal).then((next) => {
      setHistoricalOverlay(next)
      setSelectedHistory((current) => next.entries.some(
        (entry) => entry.expectation_id === current?.expectation_id,
      ) ? current : null)
      setOverlayError(null)
    }).catch((caught) => {
      if (!controller.signal.aborted) {
        setHistoricalOverlay(null)
        setSelectedHistory(null)
        setOverlayError(caught instanceof Error ? caught.message : '历史漏洞覆盖层加载失败')
      }
    })
    return () => controller.abort()
  }, [graphId])

  useEffect(() => {
    const focusNodeIds = selectedHistory?.graph_node_ids ?? (
      selectedInterface ? [selectedInterface.node_id] : []
    )
    if (!graphId || focusNodeIds.length === 0) { setResult(null); return }
    const controller = new AbortController()
    setLoading(true)
    const stateFocused = selectedInterface?.node_kind === 'state'
    void intelligenceApi.mappingGraph(graphId, {
      preset,
      focusNodeIds,
      maxHops: stateFocused ? 1 : preset === 'communication_components' ? 8 : (
        preset === 'completeness' ? 4 : 3
      ),
      maxNodes: stateFocused ? 32 : preset === 'communication_components' ? 240 : 160,
      maxEdges: stateFocused ? 64 : preset === 'communication_components' ? 480 : 320,
    }, controller.signal).then((next) => {
      setResult(next)
      setSelectedNodeId((current) => next.nodes.some(
        (node) => node.node_id === current,
      ) ? current : (
        focusNodeIds.find((nodeId) => next.nodes.some(
          (node) => node.node_id === nodeId,
        )) ?? next.nodes[0]?.node_id ?? ''
      ))
      setError(null)
    }).catch((caught) => {
      if (!controller.signal.aborted) {
        setError(caught instanceof Error ? caught.message : '通信子图加载失败')
      }
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [graphId, selectedInterface, selectedHistory, preset])

  const summary = graphs.find((graph) => graph.graph_id === graphId)
  const selectedNode = result?.nodes.find((node) => node.node_id === selectedNodeId) ?? null
  const touchingEdges = result?.edges.filter((edge) => (
    edge.source_ref === selectedNodeId || edge.target_ref === selectedNodeId
  )) ?? []
  const selectedEvidenceIds = new Set([
    ...(selectedNode?.evidence_ids ?? []),
    ...touchingEdges.flatMap((edge) => edge.evidence_ids),
  ])
  const evidence = result?.evidence_atoms.filter((atom) => (
    selectedEvidenceIds.has(atom.evidence_id)
  )) ?? []
  const historyEntries = useMemo(() => {
    const query = debouncedQuery.trim().toLowerCase()
    if (!query) return historicalOverlay?.entries ?? []
    return (historicalOverlay?.entries ?? []).filter((entry) => [
      entry.vulnerability_identifier, entry.interface_value,
      entry.handler_value, ...entry.expected_parameters,
    ].join(' ').toLowerCase().includes(query))
  }, [historicalOverlay, debouncedQuery])

  if (!loading && graphs.length === 0) {
    return <div className="grid min-h-[520px] place-items-center rounded-2xl border border-white/[0.07] bg-[#0a0f17]/75 p-8 text-center"><div><Network size={42} className="mx-auto text-cyan/30" /><h2 className="mt-4 text-sm text-slate-300">尚未发布通信架构图</h2><p className="mt-2 max-w-md text-xs leading-5 text-slate-600">先发布 Discovery Catalog 与确定性图投影；页面只查询既有事实，不会在浏览器中推断接口或 owner。</p></div></div>
  }

  return <div className="overflow-hidden rounded-2xl border border-white/[0.07] bg-[#080d15]/80 shadow-2xl shadow-black/20 backdrop-blur-xl">
    {/* Design rationale: an atlas-like three-pane graph desk keeps discovery, topology and evidence visible at once; cyan denotes exposed structure, acid green runtime facts, and ember unresolved obligations. The layout stacks on narrow screens and preserves horizontal graph panning. */}
    <div className="border-b border-white/[0.07] bg-gradient-to-r from-cyan/[0.045] via-transparent to-signal/[0.035] p-4 sm:p-5">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div><div className="eyebrow"><Network size={12} /> Communication architecture graph</div><div className="mt-2 flex flex-wrap items-baseline gap-3"><h2 className="text-lg font-semibold text-white">证据约束通信图</h2>{summary && <span className="font-mono text-[9px] text-slate-600">{summary.firmware_artifact_sha256.slice(0, 16)}…</span>}</div></div>
        <div className="flex flex-wrap gap-2">
          {summary && <><GraphMetric label="节点" value={summary.node_count} /><GraphMetric label="关系" value={summary.edge_count} /><GraphMetric label="覆盖" value={summary.source_catalog_coverage_status} /></>}
          {graphs.length > 1 && <label className="select-field"><Database size={13} /><select aria-label="选择通信架构图" value={graphId} onChange={(event) => { setGraphId(event.target.value); setSelectedInterface(null); setSelectedHistory(null); setResult(null) }}>{graphs.map((graph) => <option key={graph.graph_id} value={graph.graph_id}>{graph.firmware_artifact_sha256.slice(0, 12)} · {graph.node_count} nodes</option>)}</select></label>}
        </div>
      </div>
    </div>
    {error && <div role="alert" className="m-4 rounded-xl border border-ember/20 bg-ember/[0.06] px-4 py-3 text-xs text-ember">{error}</div>}
    <div className="grid min-h-[650px] xl:grid-cols-[270px_minmax(520px,1fr)_320px]">
      <aside className="border-b border-white/[0.07] p-4 xl:border-b-0 xl:border-r">
        <div className="grid grid-cols-2 rounded-xl border border-white/[0.07] bg-black/20 p-1"><button type="button" onClick={() => setIndexMode('interfaces')} className={`rounded-lg px-2 py-2 text-[9px] transition ${indexMode === 'interfaces' ? 'bg-cyan/[0.1] text-cyan' : 'text-slate-600'}`}><Braces size={11} className="mr-1 inline" />结构索引</button><button type="button" onClick={() => setIndexMode('history')} className={`rounded-lg px-2 py-2 text-[9px] transition ${indexMode === 'history' ? 'bg-amber-300/[0.1] text-amber-200' : 'text-slate-600'}`}><History size={11} className="mr-1 inline" />历史漏洞对照</button></div>
        <label className="search-field mt-4"><Search size={14} /><input aria-label={indexMode === 'interfaces' ? '搜索通信接口或状态' : '搜索历史漏洞'} value={interfaceQuery} onChange={(event) => setInterfaceQuery(event.target.value)} placeholder={indexMode === 'interfaces' ? '接口、操作或状态范围…' : 'CVE、接口、参数或 handler…'} /></label>
        {indexMode === 'interfaces' ? <div className="mt-3 flex items-center justify-between text-[9px] text-slate-700"><span>精确接口焦点</span><span>{interfaceIndex?.selected_node_count ?? 0} / {interfaceIndex?.total_node_count ?? 0}{interfaceIndex?.query_status === 'partial' ? ' · partial' : ''}</span></div> : <div className="mt-3 rounded-xl border border-amber-300/10 bg-amber-300/[0.035] p-3"><div className="flex items-center justify-between text-[9px]"><span className="text-amber-200">历史期望 {historicalOverlay?.total_entry_count ?? 0}</span>{historicalOverlay?.overlay.vulnerability_audit && <span className="font-mono text-slate-400">{historicalOverlay.overlay.vulnerability_audit.total_vulnerability_count}</span>}</div><p className="mt-2 text-[8px] leading-4 text-slate-600">右侧总数是漏洞库分母；图中只链接已有 Catalog 证据。</p></div>}
        <div className="mt-2 max-h-[535px] overflow-y-auto pr-1">
          {indexMode === 'interfaces' ? <>{loading && !interfaceIndex && <div className="py-10 text-center text-[10px] text-slate-700">正在装载结构索引…</div>}{interfaceIndex?.nodes.map((node) => <button key={node.node_id} type="button" aria-label={`聚焦${node.node_kind === 'state' ? '状态' : '接口'} ${node.label}`} onClick={() => { setSelectedHistory(null); setSelectedInterface(node); setSelectedNodeId(node.node_id); if (node.node_kind === 'state') setPreset('parameter_state') }} className={`group mb-1.5 w-full rounded-xl border p-3 text-left transition ${selectedInterface?.node_id === node.node_id && !selectedHistory ? 'border-cyan/30 bg-cyan/[0.075]' : 'border-transparent hover:border-white/[0.07] hover:bg-white/[0.025]'}`}><div className="flex items-start gap-2.5"><CircleDot size={14} className={`mt-0.5 shrink-0 ${node.node_kind === 'state' ? 'text-fuchsia-200' : 'text-cyan'}`} /><div className="min-w-0 flex-1"><div className="break-all font-mono text-[11px] leading-4 text-slate-200">{node.label}</div><div className="mt-1 truncate text-[9px] text-slate-700">{node.node_kind} · {node.source_path || 'derived state scope'}</div></div><ChevronRight size={13} className="mt-1 shrink-0 text-slate-700 transition group-hover:translate-x-0.5" /></div></button>)}{!loading && interfaceIndex?.nodes.length === 0 && <div className="py-10 text-center text-[10px] text-slate-700">没有符合条件的接口或状态</div>}</> : <>{overlayError && <div className="rounded-xl border border-dashed border-white/[0.08] p-4 text-center text-[9px] leading-5 text-slate-600">该图尚未发布历史漏洞覆盖层<br />{overlayError}</div>}{historyEntries.map((entry) => <button key={entry.expectation_id} type="button" aria-label={`查看历史漏洞 ${entry.vulnerability_identifier}`} onClick={() => { setSelectedInterface(null); setSelectedHistory(entry); setPreset('completeness'); setSelectedNodeId(entry.graph_node_ids[0] ?? '') }} className={`group mb-1.5 w-full rounded-xl border p-3 text-left transition ${selectedHistory?.expectation_id === entry.expectation_id ? 'border-amber-300/25 bg-amber-300/[0.065]' : 'border-transparent hover:border-white/[0.07] hover:bg-white/[0.025]'}`}><div className="flex items-center justify-between gap-2"><span className="font-mono text-[10px] text-amber-200">{entry.vulnerability_identifier}</span><HistoryStatus status={entry.status} /></div><div className="mt-2 break-all font-mono text-[9px] leading-4 text-slate-400">{entry.interface_value}</div><div className="mt-2 flex justify-between text-[8px] text-slate-700"><span>{entry.applicability}</span><span>{entry.graph_node_ids.length} graph refs</span></div></button>)}{historicalOverlay && historyEntries.length === 0 && <div className="py-10 text-center text-[10px] text-slate-700">没有符合条件的历史期望</div>}</>}
        </div>
      </aside>
      <main className="min-w-0 border-b border-white/[0.07] xl:border-b-0 xl:border-r">
        <div className="border-b border-white/[0.07] p-3 sm:p-4">
          <div className="flex gap-2 overflow-x-auto pb-1">{Object.entries(presetLabels).map(([id, label]) => <button key={id} type="button" onClick={() => setPreset(id)} className={`shrink-0 rounded-lg border px-3 py-2 text-[10px] transition ${preset === id ? 'border-cyan/25 bg-cyan/[0.08] text-cyan' : 'border-white/[0.06] text-slate-600 hover:text-slate-300'}`}>{label}</button>)}</div>
          {result && <div className="mt-3 flex flex-wrap items-center gap-3 text-[9px] text-slate-600"><span className={result.query_status === 'completed' ? 'text-signal' : 'text-amber-300'}>{result.query_status}</span><span>{result.selected_node_count} nodes</span><span>{result.selected_edge_count} edges</span><span>{Object.keys(result.facets.node_kinds).length} dimensions</span>{result.diagnostics.map((diagnostic) => <span key={diagnostic} className="text-amber-300">{diagnostic}</span>)}</div>}
        </div>
        <div className="relative min-h-[560px] overflow-auto bg-[radial-gradient(circle_at_50%_15%,rgba(117,214,255,0.055),transparent_32%),linear-gradient(rgba(255,255,255,0.018)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.018)_1px,transparent_1px)] bg-[size:auto,32px_32px,32px_32px]">
          {!selectedInterface && !selectedHistory ? <GraphPrompt /> : result ? <GraphCanvas result={result} selectedNodeId={selectedNodeId} onSelect={setSelectedNodeId} /> : <div className="grid min-h-[560px] place-items-center text-xs text-slate-700">正在恢复证据关系…</div>}
        </div>
      </main>
      <aside className="min-w-0 bg-gradient-to-b from-white/[0.02] to-transparent">
        {selectedHistory && historicalOverlay && <HistoricalEvidence entry={selectedHistory} claimBoundary={historicalOverlay.overlay.claim_boundary} />}
        {selectedNode ? <NodeEvidence node={selectedNode} evidence={evidence} edges={touchingEdges} /> : !selectedHistory && <div className="grid min-h-[420px] place-items-center p-8 text-center"><div><FileSearch size={34} className="mx-auto text-signal/25" /><h3 className="mt-4 text-sm text-slate-400">选择图中的节点</h3><p className="mt-2 text-[10px] leading-5 text-slate-700">查看身份、状态、属性、相邻关系与原始 EvidenceAtom。</p></div></div>}
      </aside>
    </div>
  </div>
}

function GraphMetric({ label, value }: { label: string; value: number | string }) {
  return <div className="min-w-[74px] rounded-xl border border-white/[0.07] bg-black/20 px-3 py-2"><div className="text-[8px] uppercase tracking-[0.14em] text-slate-700">{label}</div><div className="mt-1 font-mono text-xs font-semibold text-slate-300">{typeof value === 'number' ? value.toLocaleString('en-US') : value}</div></div>
}

function GraphPrompt() {
  return <div className="grid min-h-[560px] place-items-center p-8 text-center"><div><GitBranch size={42} className="mx-auto text-cyan/25" /><h3 className="mt-4 text-sm font-medium text-slate-300">从一个接口开始恢复结构</h3><p className="mt-2 max-w-sm text-xs leading-6 text-slate-600">选择左侧接口，沿已验证语义边展开参数、分发、处理主体和未决义务。同文件中的无关节点不会被带入。</p></div></div>
}

function GraphCanvas({ result, selectedNodeId, onSelect }: { result: CommunicationGraphQueryResult; selectedNodeId: string; onSelect: (id: string) => void }) {
  const layout = useMemo(() => layoutNodes(result.nodes), [result.nodes])
  const byId = new Map(layout.nodes.map((item) => [item.node.node_id, item]))
  return <div className="relative" style={{ width: layout.width, height: layout.height }}>
    <svg aria-label="通信架构关系" className="pointer-events-none absolute inset-0" width={layout.width} height={layout.height}>
      <defs><marker id="graph-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="rgba(117,214,255,.42)" /></marker></defs>
      {result.edges.map((edge) => {
        const source = byId.get(edge.source_ref); const target = byId.get(edge.target_ref)
        if (!source || !target) return null
        const sx = source.x + 156; const sy = source.y + 32; const tx = target.x; const ty = target.y + 32
        const bend = Math.max(24, Math.abs(tx - sx) * 0.42)
        return <path key={edge.edge_id} d={`M ${sx} ${sy} C ${sx + bend} ${sy}, ${tx - bend} ${ty}, ${tx} ${ty}`} fill="none" stroke={edge.status === 'open' ? 'rgba(255,138,101,.42)' : 'rgba(117,214,255,.27)'} strokeWidth="1.25" markerEnd="url(#graph-arrow)"><title>{edge.edge_kind} · {edge.status}</title></path>
      })}
    </svg>
    {layout.nodes.map(({ node, x, y }) => <button key={node.node_id} type="button" aria-label={`查看图节点 ${node.label}`} onClick={() => onSelect(node.node_id)} title={`${node.node_kind} · ${node.status}`} className={`absolute h-16 w-[156px] overflow-hidden rounded-xl border p-2.5 text-left shadow-lg shadow-black/20 transition hover:-translate-y-0.5 hover:brightness-110 ${nodeTone[node.node_kind] ?? 'border-white/[0.12] bg-[#111925] text-slate-300'} ${selectedNodeId === node.node_id ? 'ring-2 ring-white/25' : ''}`} style={{ left: x, top: y }}><div className="flex items-center justify-between gap-2"><span className="truncate text-[8px] font-semibold uppercase tracking-[0.12em] opacity-65">{node.node_kind.replaceAll('_', ' ')}</span><span className={`h-1.5 w-1.5 shrink-0 rounded-full ${node.status === 'open' ? 'bg-ember' : 'bg-current'}`} /></div><div className="mt-1.5 line-clamp-2 break-all font-mono text-[10px] leading-4">{node.label}</div></button>)}
  </div>
}

function layoutNodes(nodes: CommunicationGraphNode[]) {
  const grouped = new Map<number, CommunicationGraphNode[]>()
  nodes.forEach((node) => {
    const rank = kindRank[node.node_kind] ?? 3
    grouped.set(rank, [...(grouped.get(rank) ?? []), node])
  })
  const positioned: PositionedNode[] = []
  let maxColumn = 0; let maxRows = 0
  Array.from(grouped.entries()).sort(([a], [b]) => a - b).forEach(([, items], column) => {
    maxColumn = Math.max(maxColumn, column); maxRows = Math.max(maxRows, items.length)
    items.sort((a, b) => a.node_id.localeCompare(b.node_id)).forEach((node, row) => {
      positioned.push({ node, x: 34 + column * 200, y: 34 + row * 86 })
    })
  })
  return { nodes: positioned, width: Math.max(720, 34 + (maxColumn + 1) * 200), height: Math.max(560, 34 + maxRows * 86) }
}

function HistoryStatus({ status }: { status: HistoricalGraphOverlayEntry['status'] }) {
  const labels = {
    observed: '已发现', partial: '部分发现', missing: '未发现', not_assessable: '不可判定',
  }
  const tone = status === 'observed' ? 'bg-signal/[0.08] text-signal' : status === 'missing' ? 'bg-ember/[0.09] text-ember' : 'bg-amber-300/[0.08] text-amber-200'
  return <span className={`rounded-md px-1.5 py-0.5 text-[8px] ${tone}`}>{labels[status]}</span>
}

function HistoricalEvidence({ entry, claimBoundary }: { entry: HistoricalGraphOverlayEntry; claimBoundary: string }) {
  const crossVersion = entry.applicability !== 'exact_artifact'
  return <article className="detail-enter border-b border-amber-300/10 bg-amber-300/[0.025] p-5">
    <div className="eyebrow text-amber-200"><History size={12} /> Historical expectation</div>
    <div className="mt-3 flex items-start justify-between gap-3"><div><h3 className="font-mono text-sm font-semibold text-white">{entry.vulnerability_identifier}</h3><div className="mt-1 break-all font-mono text-[10px] text-slate-400">{entry.interface_value}</div></div><HistoryStatus status={entry.status} /></div>
    <div className="mt-3 grid grid-cols-2 gap-2 text-[8px]"><div className="rounded-lg border border-white/[0.06] p-2"><div className="text-slate-700">适用性</div><div className="mt-1 text-amber-200">{entry.applicability}</div></div><div className="rounded-lg border border-white/[0.06] p-2"><div className="text-slate-700">路由绑定</div><div className="mt-1 break-all text-slate-300">{entry.route_binding_status ?? '未提供'}</div></div></div>
    {crossVersion && <div className="mt-3 rounded-lg border border-amber-300/15 bg-amber-300/[0.045] p-2.5 text-[9px] leading-5 text-amber-100">跨版本结构存在，不代表当前固件存在该漏洞</div>}
    <div className="mt-4 space-y-3 text-[9px] leading-5"><div><div className="text-[8px] uppercase tracking-wider text-slate-700">期望 / 已观察参数</div><div className="mt-1 break-all font-mono text-slate-400">{entry.expected_parameters.join(', ') || '无'} / {entry.observed_parameters.join(', ') || '无'}</div>{entry.missing_parameters.length > 0 && <div className="mt-1 font-mono text-ember">缺失: {entry.missing_parameters.join(', ')}</div>}</div><div><div className="text-[8px] uppercase tracking-wider text-slate-700">Handler evidence</div><div className="mt-1 break-all font-mono text-slate-400">{entry.observed_handlers.join(', ') || '未观察到'}</div></div><div><div className="text-[8px] uppercase tracking-wider text-slate-700">差异解释</div><p className="mt-1 text-slate-500">{entry.gap_explanation}</p></div><div><div className="text-[8px] uppercase tracking-wider text-slate-700">版本边界依据</div><p className="mt-1 text-slate-500">{entry.applicability_basis || '未提供版本适用性依据'}</p></div></div>
    <div className="mt-4 rounded-lg border border-white/[0.06] p-2.5 text-[8px] leading-4 text-slate-700">{claimBoundary}</div>
  </article>
}

function NodeEvidence({ node, evidence, edges }: { node: CommunicationGraphNode; evidence: CommunicationGraphEvidenceAtom[]; edges: CommunicationGraphEdge[] }) {
  return <article className="detail-enter max-h-[650px] overflow-y-auto p-5">
    <div className="eyebrow">{node.node_kind === 'obligation' ? <ShieldQuestion size={12} /> : <Layers3 size={12} />} Node evidence</div>
    <h3 className="mt-3 break-all font-mono text-base font-semibold leading-6 text-white">{node.label}</h3>
    <div className="mt-3 flex flex-wrap gap-2"><span className="rounded-lg bg-cyan/[0.07] px-2 py-1 text-[9px] text-cyan">{node.node_kind}</span><span className={`rounded-lg px-2 py-1 text-[9px] ${node.status === 'open' ? 'bg-ember/[0.08] text-ember' : 'bg-signal/[0.07] text-signal'}`}>{node.status}</span></div>
    <EvidenceBlock icon={<Boxes size={12} />} title="来源制品"><div className="break-all font-mono text-[9px] leading-5 text-slate-500">{node.source_path || '未声明单一来源路径'}</div></EvidenceBlock>
    <EvidenceBlock icon={<Activity size={12} />} title="结构属性">{node.attributes.length ? <div className="space-y-2">{node.attributes.map(([key, value]) => <div key={`${key}:${value}`} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2.5"><div className="text-[8px] uppercase tracking-[0.1em] text-slate-700">{key.replaceAll('_', ' ')}</div><div className="mt-1 break-all font-mono text-[9px] leading-4 text-slate-400">{value}</div></div>)}</div> : <MutedEvidence />}</EvidenceBlock>
    <EvidenceBlock icon={<GitBranch size={12} />} title="相邻语义关系">{edges.length ? <div className="space-y-2">{edges.map((edge) => <div key={edge.edge_id} className="rounded-lg border border-white/[0.06] p-2.5"><div className="text-[9px] text-cyan">{edge.edge_kind}</div><div className="mt-1 break-all font-mono text-[8px] leading-4 text-slate-700">{edge.source_ref === node.node_id ? `→ ${edge.target_ref}` : `← ${edge.source_ref}`}</div></div>)}</div> : <MutedEvidence />}</EvidenceBlock>
    <EvidenceBlock icon={<FileSearch size={12} />} title="Evidence atoms">{evidence.length ? <div className="space-y-2">{evidence.map((atom) => <div key={atom.evidence_id} className="rounded-lg border border-signal/10 bg-signal/[0.025] p-3"><div className="flex items-start justify-between gap-2"><span className="text-[10px] font-medium text-signal">{atom.capability}</span><span className="font-mono text-[8px] text-slate-700">{Math.round(atom.confidence * 100)}%</span></div><div className="mt-2 break-all font-mono text-[9px] leading-4 text-slate-500">{atom.source_span.artifact_path}</div><div className="mt-1 break-all font-mono text-[8px] leading-4 text-slate-700">{atom.source_span.locator}</div></div>)}</div> : <MutedEvidence />}</EvidenceBlock>
    {node.status === 'open' && <div className="mt-5 flex gap-2 rounded-xl border border-ember/15 bg-ember/[0.04] p-3 text-[9px] leading-5 text-slate-500"><AlertTriangle size={14} className="mt-0.5 shrink-0 text-ember" />未决义务表示仍需指定证据能力；图谱不会把相邻线索自动提升为 owner 或漏洞结论。</div>}
  </article>
}

function EvidenceBlock({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return <section className="mt-5"><h4 className="mb-2 flex items-center gap-2 text-[9px] font-semibold uppercase tracking-[0.13em] text-slate-600">{icon}{title}</h4>{children}</section>
}

function MutedEvidence() { return <div className="rounded-lg border border-dashed border-white/[0.06] py-4 text-center text-[9px] text-slate-700">当前查询未返回该类证据</div> }
