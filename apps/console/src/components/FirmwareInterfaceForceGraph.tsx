import {
  Binary, Box, Braces, ChevronDown, ChevronRight, CircleDot, Crosshair,
  GitBranch, Info, Network, RotateCcw, Search, ShieldQuestion,
} from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { PointerEvent as ReactPointerEvent, ReactNode, WheelEvent as ReactWheelEvent } from 'react'
import type {
  InterfaceForceGraph, InterfaceForceGraphEdge, InterfaceForceGraphNode,
} from '../types'

type Position = { x: number; y: number }
type ForceLayout = { positions: Map<string, Position>; width: number; height: number }
type SimulationState = ForceLayout & {
  velocities: Map<string, Position>
  pinned: Set<string>
  alpha: number
}

const nodeWidth: Record<InterfaceForceGraphNode['node_kind'], number> = {
  firmware: 230, component: 196, interface: 210, parameter: 164,
}
const nodeHeight: Record<InterfaceForceGraphNode['node_kind'], number> = {
  firmware: 68, component: 62, interface: 60, parameter: 54,
}
const depthByKind: Record<InterfaceForceGraphNode['node_kind'], number> = {
  firmware: 0, component: 1, interface: 2, parameter: 3,
}

function hashFraction(value: string): number {
  let hash = 2166136261
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index)
    hash = Math.imul(hash, 16777619)
  }
  return (hash >>> 0) / 0xffffffff
}

function createSimulation(
  nodes: InterfaceForceGraphNode[], edges: InterfaceForceGraphEdge[], seed: number,
): SimulationState {
  const count = Math.max(1, nodes.length)
  const width = Math.max(1120, Math.ceil(Math.sqrt(count)) * 320)
  const depthCounts = [0, 0, 0, 0]
  nodes.forEach((node) => { depthCounts[depthByKind[node.node_kind]] += 1 })
  const bandWidth = Math.max(240, width * 0.22)
  const columnsPerBand = Math.max(1, Math.floor(bandWidth / 265))
  const requiredRows = Math.max(...depthCounts.map((value) => Math.ceil(value / columnsPerBand)))
  const height = Math.max(680, Math.ceil(Math.sqrt(count)) * 150, requiredRows * 92 + 180)
  const positions = new Map<string, Position>()
  const velocities = new Map<string, Position>()
  const column = [130, width * 0.29, width * 0.59, width * 0.84]

  nodes.forEach((node, index) => {
    const depth = depthByKind[node.node_kind]
    const jitter = hashFraction(`${node.node_id}:${seed}`)
    positions.set(node.node_id, {
      x: column[depth] + (jitter - 0.5) * bandWidth * 0.86,
      y: 90 + ((index * 97 + jitter * height) % Math.max(240, height - 180)),
    })
    velocities.set(node.node_id, { x: 0, y: 0 })
  })

  return { positions, velocities, width, height, pinned: new Set(), alpha: 1 }
}

function tickSimulation(
  simulation: SimulationState,
  nodes: InterfaceForceGraphNode[], edges: InterfaceForceGraphEdge[], iterations = 1,
) {
  const column = [130, simulation.width * 0.29, simulation.width * 0.59, simulation.width * 0.84]
  const columnStrength = nodes.length > 80 ? 0.004 : 0.018
  for (let iteration = 0; iteration < iterations; iteration += 1) {
    for (let left = 0; left < nodes.length; left += 1) {
      for (let right = left + 1; right < nodes.length; right += 1) {
        const leftNode = nodes[left]
        const rightNode = nodes[right]
        const a = simulation.positions.get(leftNode.node_id)!
        const b = simulation.positions.get(rightNode.node_id)!
        let dx = b.x - a.x
        let dy = b.y - a.y
        const distanceSquared = Math.max(1800, dx * dx + dy * dy)
        const distance = Math.sqrt(distanceSquared)
        dx /= distance
        dy /= distance
        const force = Math.min(4.5, 38000 / distanceSquared) * simulation.alpha
        const va = simulation.velocities.get(leftNode.node_id)!
        const vb = simulation.velocities.get(rightNode.node_id)!
        va.x -= dx * force; va.y -= dy * force
        vb.x += dx * force; vb.y += dy * force

        // Rectangle-aware collision: node cards separate by their actual footprint,
        // not merely by center-point distance.
        const overlapX = (nodeWidth[leftNode.node_kind] + nodeWidth[rightNode.node_kind]) / 2 + 22 - Math.abs(b.x - a.x)
        const overlapY = (nodeHeight[leftNode.node_kind] + nodeHeight[rightNode.node_kind]) / 2 + 18 - Math.abs(b.y - a.y)
        if (overlapX > 0 && overlapY > 0) {
          if (overlapX < overlapY) {
            const direction = b.x >= a.x ? 1 : -1
            va.x -= direction * overlapX * 0.18
            vb.x += direction * overlapX * 0.18
          } else {
            const direction = b.y >= a.y ? 1 : -1
            va.y -= direction * overlapY * 0.22
            vb.y += direction * overlapY * 0.22
          }
        }
      }
    }
    edges.forEach((edge) => {
      const source = simulation.positions.get(edge.source_ref)
      const target = simulation.positions.get(edge.target_ref)
      if (!source || !target) return
      const dx = target.x - source.x
      const dy = target.y - source.y
      const distance = Math.max(1, Math.sqrt(dx * dx + dy * dy))
      const rest = edge.edge_kind === 'accepts' ? 160 : 210
      const force = (distance - rest) * 0.014 * simulation.alpha
      const vx = dx / distance * force
      const vy = dy / distance * force
      const sourceVelocity = simulation.velocities.get(edge.source_ref)!
      const targetVelocity = simulation.velocities.get(edge.target_ref)!
      sourceVelocity.x += vx; sourceVelocity.y += vy
      targetVelocity.x -= vx; targetVelocity.y -= vy
    })
    nodes.forEach((node) => {
      const point = simulation.positions.get(node.node_id)!
      const velocity = simulation.velocities.get(node.node_id)!
      const depth = depthByKind[node.node_kind]
      velocity.x += (column[depth] - point.x) * columnStrength * simulation.alpha
      velocity.y += (simulation.height / 2 - point.y) * 0.0018 * simulation.alpha
      velocity.x *= 0.72; velocity.y *= 0.72
      if (!simulation.pinned.has(node.node_id)) {
        point.x = Math.max(45, Math.min(simulation.width - 45, point.x + velocity.x))
        point.y = Math.max(45, Math.min(simulation.height - 45, point.y + velocity.y))
      }
    })
    // A final positional projection makes non-overlap a hard invariant even while
    // link springs and pointer reheating continue to move the graph.
    for (let pass = 0; pass < 16; pass += 1) {
      let corrected = false
      for (let left = 0; left < nodes.length; left += 1) {
        for (let right = left + 1; right < nodes.length; right += 1) {
          const leftNode = nodes[left]
          const rightNode = nodes[right]
          const a = simulation.positions.get(leftNode.node_id)!
          const b = simulation.positions.get(rightNode.node_id)!
          const overlapX = (nodeWidth[leftNode.node_kind] + nodeWidth[rightNode.node_kind]) / 2 + 12 - Math.abs(b.x - a.x)
          const overlapY = (nodeHeight[leftNode.node_kind] + nodeHeight[rightNode.node_kind]) / 2 + 12 - Math.abs(b.y - a.y)
          if (overlapX <= 0 || overlapY <= 0) continue
          const leftPinned = simulation.pinned.has(leftNode.node_id)
          const rightPinned = simulation.pinned.has(rightNode.node_id)
          if (leftPinned && rightPinned) continue
          corrected = true
          if (overlapX < overlapY) {
            const direction = b.x >= a.x ? 1 : -1
            const shift = overlapX + 0.8
            if (!leftPinned) a.x -= direction * (rightPinned ? shift : shift / 2)
            if (!rightPinned) b.x += direction * (leftPinned ? shift : shift / 2)
          } else {
            const direction = b.y >= a.y ? 1 : -1
            const shift = overlapY + 0.8
            if (!leftPinned) a.y -= direction * (rightPinned ? shift : shift / 2)
            if (!rightPinned) b.y += direction * (leftPinned ? shift : shift / 2)
          }
          a.x = Math.max(45, Math.min(simulation.width - 45, a.x))
          a.y = Math.max(45, Math.min(simulation.height - 45, a.y))
          b.x = Math.max(45, Math.min(simulation.width - 45, b.x))
          b.y = Math.max(45, Math.min(simulation.height - 45, b.y))
        }
      }
      if (!corrected) break
    }
    simulation.alpha *= 0.965
  }
}

function useDynamicForceLayout(
  nodes: InterfaceForceGraphNode[], edges: InterfaceForceGraphEdge[], seed: number,
) {
  const [layout, setLayout] = useState<ForceLayout>(() => {
    const simulation = createSimulation(nodes, edges, seed)
    tickSimulation(simulation, nodes, edges, 36)
    return { positions: new Map(simulation.positions), width: simulation.width, height: simulation.height }
  })
  const simulationRef = useRef<SimulationState | null>(null)
  const wakeRef = useRef<(alpha?: number) => void>(() => undefined)

  useEffect(() => {
    const simulation = createSimulation(nodes, edges, seed)
    tickSimulation(simulation, nodes, edges, 36)
    simulationRef.current = simulation
    setLayout({ positions: new Map(simulation.positions), width: simulation.width, height: simulation.height })
    let frame: number | null = null
    let disposed = false
    const schedule = (callback: FrameRequestCallback) => (
      typeof requestAnimationFrame === 'function'
        ? requestAnimationFrame(callback)
        : window.setTimeout(() => callback(performance.now()), 16)
    )
    const cancel = (handle: number) => {
      if (typeof cancelAnimationFrame === 'function') cancelAnimationFrame(handle)
      else window.clearTimeout(handle)
    }
    const animate = () => {
      frame = null
      if (disposed) return
      tickSimulation(simulation, nodes, edges, nodes.length > 160 ? 1 : 2)
      setLayout({ positions: new Map(simulation.positions), width: simulation.width, height: simulation.height })
      if (simulation.alpha > 0.018 || simulation.pinned.size) frame = schedule(animate)
    }
    wakeRef.current = (alpha = 0.72) => {
      simulation.alpha = Math.max(simulation.alpha, alpha)
      if (frame === null) frame = schedule(animate)
    }
    wakeRef.current(0.8)
    return () => {
      disposed = true
      if (frame !== null) cancel(frame)
      simulationRef.current = null
    }
  }, [nodes, edges, seed])

  const dragBy = (nodeId: string, dx: number, dy: number) => {
    const simulation = simulationRef.current
    const point = simulation?.positions.get(nodeId)
    if (!simulation || !point) return
    simulation.pinned.add(nodeId)
    point.x = Math.max(45, Math.min(simulation.width - 45, point.x + dx))
    point.y = Math.max(45, Math.min(simulation.height - 45, point.y + dy))
    simulation.velocities.set(nodeId, { x: 0, y: 0 })
    setLayout({ positions: new Map(simulation.positions), width: simulation.width, height: simulation.height })
    wakeRef.current(0.92)
  }
  const release = (nodeId: string) => {
    simulationRef.current?.pinned.delete(nodeId)
    wakeRef.current(0.86)
  }
  let visibleLayout = layout
  if (nodes.some((node) => !layout.positions.has(node.node_id))) {
    const fallback = createSimulation(nodes, edges, seed)
    tickSimulation(fallback, nodes, edges, 36)
    visibleLayout = {
      positions: new Map(fallback.positions), width: fallback.width, height: fallback.height,
    }
  }
  return { layout: visibleLayout, dragBy, release }
}

function visibleProjection(
  graph: InterfaceForceGraph, expanded: Set<string>, query: string,
): { nodes: InterfaceForceGraphNode[]; edges: InterfaceForceGraphEdge[] } {
  const byId = new Map(graph.nodes.map((node) => [node.node_id, node]))
  const visible = new Set<string>()
  const visit = (nodeId: string) => {
    const node = byId.get(nodeId)
    if (!node) return
    visible.add(nodeId)
    if (expanded.has(nodeId)) node.child_ids.forEach(visit)
  }
  const normalized = query.trim().toLowerCase()
  if (normalized) {
    graph.nodes.filter((node) => node.label.toLowerCase().includes(normalized)).forEach((node) => {
      let current: InterfaceForceGraphNode | undefined = node
      while (current) {
        visible.add(current.node_id)
        current = current.parent_id ? byId.get(current.parent_id) : undefined
      }
      if (expanded.has(node.node_id)) node.child_ids.forEach(visit)
    })
    visible.add(graph.root_node_id)
  } else {
    visit(graph.root_node_id)
  }
  return {
    nodes: graph.nodes.filter((node) => visible.has(node.node_id)),
    edges: graph.edges.filter((edge) => visible.has(edge.source_ref) && visible.has(edge.target_ref)),
  }
}

export function FirmwareInterfaceForceGraph({ graph }: { graph: InterfaceForceGraph }) {
  const root = graph.nodes.find((node) => node.node_id === graph.root_node_id)
  const [expanded, setExpanded] = useState(() => new Set([graph.root_node_id]))
  const [selectedId, setSelectedId] = useState(graph.root_node_id)
  const [query, setQuery] = useState('')
  const [layoutSeed, setLayoutSeed] = useState(0)
  const [layoutNotice, setLayoutNotice] = useState('')
  const [hoveredId, setHoveredId] = useState<string | null>(null)
  const [zoom, setZoom] = useState(1)
  const dragRef = useRef<{ nodeId: string; x: number; y: number; moved: boolean } | null>(null)
  const projection = useMemo(
    () => visibleProjection(graph, expanded, query), [graph, expanded, query],
  )
  const { layout, dragBy, release } = useDynamicForceLayout(
    projection.nodes, projection.edges, layoutSeed,
  )
  const selected = graph.nodes.find((node) => node.node_id === selectedId) ?? root
  const byId = useMemo(() => new Map(graph.nodes.map((node) => [node.node_id, node])), [graph.nodes])

  const toggle = (nodeId: string) => {
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(nodeId)) next.delete(nodeId)
      else next.add(nodeId)
      return next
    })
    setSelectedId(nodeId)
  }
  const resetLayout = () => {
    setLayoutSeed((current) => current + 1)
    setLayoutNotice('自动布局已重置')
  }
  const highlighted = useMemo(() => {
    if (!hoveredId) return new Set<string>()
    const result = new Set([hoveredId])
    projection.edges.forEach((edge) => {
      if (edge.source_ref === hoveredId) result.add(edge.target_ref)
      if (edge.target_ref === hoveredId) result.add(edge.source_ref)
    })
    return result
  }, [hoveredId, projection.edges])
  const beginDrag = (node: InterfaceForceGraphNode, event: ReactPointerEvent<SVGForeignObjectElement>) => {
    dragRef.current = { nodeId: node.node_id, x: event.clientX, y: event.clientY, moved: false }
    event.currentTarget.setPointerCapture?.(event.pointerId)
    setSelectedId(node.node_id)
  }
  const continueDrag = (event: ReactPointerEvent<SVGForeignObjectElement>) => {
    const active = dragRef.current
    if (!active) return
    const dx = (event.clientX - active.x) / zoom
    const dy = (event.clientY - active.y) / zoom
    if (Math.abs(dx) + Math.abs(dy) < 0.5) return
    active.x = event.clientX; active.y = event.clientY; active.moved = true
    dragBy(active.nodeId, dx, dy)
  }
  const endDrag = (event: ReactPointerEvent<SVGForeignObjectElement>) => {
    const active = dragRef.current
    if (!active) return
    event.currentTarget.releasePointerCapture?.(event.pointerId)
    release(active.nodeId)
    if (active.moved) {
      const node = byId.get(active.nodeId)
      setLayoutNotice(`已拖动节点 ${node?.label ?? active.nodeId}；碰撞力正在重新分离邻近节点`)
    }
    dragRef.current = null
  }
  const handleWheel = (event: ReactWheelEvent<SVGSVGElement>) => {
    event.preventDefault()
    setZoom((current) => Math.max(0.45, Math.min(1.8, current * (event.deltaY > 0 ? 0.9 : 1.1))))
  }

  return <section className="detail-enter overflow-hidden rounded-2xl border border-white/[0.07] bg-[#080d14]/90 backdrop-blur-xl">
    {/* Design rationale: progressive disclosure keeps AC9's large interface set legible;
        the evidence panel stays spatially stable while a force simulation optimizes each expansion. */}
    <header className="flex flex-col gap-4 border-b border-white/[0.07] p-4 lg:flex-row lg:items-center lg:justify-between">
      <div>
        <div className="eyebrow"><Network size={12} /> Expandable interface force graph</div>
        <h2 className="mt-2 text-base font-semibold text-white">固件 → 二进制 → 接口 → 参数</h2>
        <p className="mt-1 text-[10px] text-slate-600">拖拽节点 · 滚轮缩放 · 悬停高亮邻接关系</p>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <label className="search-field w-[260px]"><Search size={14} /><input aria-label="搜索力导图节点" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索 httpd、接口或参数…" /></label>
        <button type="button" aria-label="重新自动布局" onClick={resetLayout} className="inline-flex items-center gap-2 rounded-xl border border-white/[0.07] bg-white/[0.025] px-3 py-2.5 text-[10px] text-slate-400 transition hover:text-cyan"><RotateCcw size={13} />重新布局</button>
      </div>
    </header>
    <div className="grid grid-cols-2 border-b border-white/[0.06] sm:grid-cols-4">
      <Metric label="二进制组件" value={graph.summary.binary_component_count} />
      <Metric label="接口" value={graph.summary.interface_count} />
      <Metric label="输入参数" value={graph.summary.parameter_count} />
      <Metric label="类型待恢复" value={graph.summary.unknown_parameter_type_count} warning />
    </div>
    {layoutNotice && <div role="status" className="border-b border-signal/10 bg-signal/[0.035] px-4 py-2 text-[10px] text-signal">{layoutNotice}</div>}
    <div className="grid min-h-[680px] xl:grid-cols-[minmax(0,1fr)_370px]">
      <div className="min-w-0 border-b border-white/[0.07] xl:border-b-0 xl:border-r">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] px-4 py-3">
          <div className="flex flex-wrap gap-3 text-[9px] text-slate-600">
            <Legend color="bg-signal" label="固件" /><Legend color="bg-cyan" label="二进制 / 组件" />
            <Legend color="bg-violet-400" label="接口" /><Legend color="bg-amber-300" label="参数" />
          </div>
          <div className="font-mono text-[9px] text-slate-600">可见 {projection.nodes.length} / {graph.nodes.length} nodes · {projection.edges.length} edges</div>
        </div>
        <div className="max-h-[690px] overflow-auto bg-[radial-gradient(circle_at_50%_45%,rgba(73,214,179,0.045),transparent_38%),linear-gradient(rgba(255,255,255,0.018)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.018)_1px,transparent_1px)] bg-[size:auto,34px_34px,34px_34px]">
          <svg aria-label="固件接口力导向图" width={layout.width} height={layout.height} className="block touch-none" onWheel={handleWheel}>
            <defs><filter id="force-glow"><feGaussianBlur stdDeviation="3" result="blur" /><feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge></filter></defs>
            <g transform={`scale(${zoom})`} style={{ transformOrigin: '0 0' }}>
            {projection.edges.map((edge) => {
              const source = layout.positions.get(edge.source_ref)!
              const target = layout.positions.get(edge.target_ref)!
              const active = !hoveredId || edge.source_ref === hoveredId || edge.target_ref === hoveredId
              return <g key={edge.edge_id} opacity={active ? 1 : 0.12} className="transition-opacity"><line x1={source.x} y1={source.y} x2={target.x} y2={target.y} stroke={edge.edge_kind === 'accepts' ? 'rgba(252,211,77,.42)' : 'rgba(99,203,232,.34)'} strokeWidth={active && hoveredId ? '2.2' : '1.3'} /><circle cx={(source.x + target.x) / 2} cy={(source.y + target.y) / 2} r="2" fill="rgba(183,243,107,.5)" /></g>
            })}
            {projection.nodes.map((node) => {
              const point = layout.positions.get(node.node_id)!
              const width = nodeWidth[node.node_kind]
              const height = nodeHeight[node.node_kind]
              const active = !hoveredId || highlighted.has(node.node_id)
              return <foreignObject key={node.node_id} x={point.x - width / 2} y={point.y - height / 2} width={width} height={height} className="cursor-grab overflow-visible transition-opacity active:cursor-grabbing" opacity={active ? 1 : 0.18}
                onPointerDown={(event) => beginDrag(node, event)} onPointerMove={continueDrag} onPointerUp={endDrag} onPointerCancel={endDrag}
                onMouseEnter={() => setHoveredId(node.node_id)} onMouseLeave={() => setHoveredId(null)}>
                <ForceNode node={node} selected={selected?.node_id === node.node_id} expanded={expanded.has(node.node_id)} onSelect={() => setSelectedId(node.node_id)} onToggle={() => toggle(node.node_id)} />
              </foreignObject>
            })}
            </g>
          </svg>
        </div>
      </div>
      <aside className="min-w-0 bg-[radial-gradient(circle_at_100%_0%,rgba(183,243,107,0.055),transparent_32%)]">
        {selected ? <NodeDetail node={selected} parent={selected.parent_id ? byId.get(selected.parent_id) : undefined} grandparent={selected.parent_id ? byId.get(byId.get(selected.parent_id)?.parent_id ?? '') : undefined} /> : null}
      </aside>
    </div>
    <footer className="border-t border-white/[0.06] px-4 py-3 text-[9px] leading-5 text-slate-700"><ShieldQuestion size={11} className="mr-2 inline" />{graph.claim_boundary}</footer>
  </section>
}

function Legend({ color, label }: { color: string; label: string }) {
  return <span className="inline-flex items-center gap-1.5"><i className={`h-1.5 w-1.5 rounded-full ${color}`} />{label}</span>
}

function Metric({ label, value, warning = false }: { label: string; value: number; warning?: boolean }) {
  return <div className="border-r border-white/[0.05] px-4 py-3 last:border-r-0"><div className="text-[8px] uppercase tracking-[0.12em] text-slate-700">{label}</div><div className={`mt-1 font-mono text-lg font-semibold ${warning ? 'text-amber-300' : 'text-slate-200'}`}>{value}</div></div>
}

function ForceNode({ node, selected, expanded, onSelect, onToggle }: {
  node: InterfaceForceGraphNode; selected: boolean; expanded: boolean
  onSelect: () => void; onToggle: () => void
}) {
  const style = {
    firmware: 'border-signal/35 bg-[#112018]/95 text-signal',
    component: 'border-cyan/30 bg-[#0c1a23]/95 text-cyan',
    interface: 'border-violet-400/25 bg-[#141323]/95 text-violet-200',
    parameter: 'border-amber-300/25 bg-[#211b10]/95 text-amber-200',
  }[node.node_kind]
  const Icon = { firmware: Crosshair, component: Binary, interface: Braces, parameter: CircleDot }[node.node_kind]
  const kindLabel = { firmware: '固件', component: '组件', interface: '接口', parameter: '参数' }[node.node_kind]
  return <div className={`flex h-full w-full items-center gap-2 rounded-xl border p-2 shadow-[0_12px_30px_rgba(0,0,0,.32)] transition ${style} ${selected ? 'ring-1 ring-white/20' : ''}`}>
    <button type="button" aria-label={node.node_kind === 'parameter' ? `选择参数 ${node.label}` : `选择节点 ${node.label}`} onClick={onSelect} className="flex min-w-0 flex-1 items-center gap-2 text-left">
      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-black/25"><Icon size={14} /></span>
      <span className="min-w-0"><span className="block text-[8px] uppercase tracking-[0.14em] opacity-50">{kindLabel}</span><span className="block truncate font-mono text-[10px] text-slate-100" title={node.label}>{node.label}</span></span>
    </button>
    {node.expandable && <button type="button" aria-label={`${expanded ? '折叠' : '展开'}${kindLabel} ${node.label}`} onClick={onToggle} className="grid h-7 w-7 shrink-0 place-items-center rounded-lg border border-white/[0.06] bg-black/20 text-slate-500 hover:text-white">{expanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}</button>}
  </div>
}

function NodeDetail({ node, parent, grandparent }: {
  node: InterfaceForceGraphNode
  parent?: InterfaceForceGraphNode
  grandparent?: InterfaceForceGraphNode
}) {
  const details = node.details
  const title = { firmware: '固件详情', component: '组件详情', interface: '接口详情', parameter: '参数详情' }[node.node_kind]
  const constraints = asRecords(details.constraints)
  const dependencies = asRecords(details.dependencies)
  const evidence = asRecords(details.evidence_locations)
  const ownerInterface = node.node_kind === 'parameter' ? parent : node.node_kind === 'interface' ? node : undefined
  return <article className="max-h-[690px] overflow-y-auto p-5">
    <div className="eyebrow"><Info size={12} /> {title}</div>
    <h3 className="mt-3 break-all font-mono text-lg font-semibold text-white">{node.label}</h3>
    <div className="mt-2 flex flex-wrap gap-2 text-[9px]"><span className="rounded bg-white/[0.04] px-2 py-1 text-slate-500">{node.node_kind}</span><span className="rounded bg-signal/[0.05] px-2 py-1 text-signal">{node.status}</span></div>
    {node.node_kind === 'parameter' && <>
      <DetailSection title="参数语义"><DetailGrid items={[
        ['输入位置', stringValue(details.namespace)],
        ['参数角色', stringValue(details.parameter_role)],
        ['数据类型', stringValue(details.data_type)],
        ['类型依据', stringValue(details.data_type_basis)],
      ]} /><p className="mt-3 rounded-xl border border-white/[0.06] bg-white/[0.02] p-3 text-[10px] leading-5 text-slate-500">{stringValue(details.function_summary)}</p></DetailSection>
      <DetailSection title="所属接口与处理组件"><DetailGrid items={[
        ['接口', ownerInterface?.label ?? '未关联'],
        ['组件', grandparent?.label ?? '未关联'],
        ['Handler', stringValue(ownerInterface?.details.handler_symbol)],
        ['Handler identity', stringValue(ownerInterface?.details.handler_identity)],
      ]} /></DetailSection>
      <DetailSection title="取值与代码约束"><div className="rounded-xl border border-amber-300/10 bg-amber-300/[0.03] p-3"><div className="text-[9px] uppercase tracking-[0.12em] text-slate-600">观察值域</div><div className="mt-2 font-mono text-xs text-amber-200">{asStrings(details.allowed_values).join(' · ') || '未恢复'}</div></div>{constraints.map((item, index) => <div key={`${item.kind}:${index}`} className="mt-2 rounded-xl border border-white/[0.06] p-3"><div className="flex justify-between gap-3 text-[9px]"><span className="font-mono text-cyan">{stringValue(item.kind)}</span><span className="text-slate-600">{stringValue(item.status)}</span></div><p className="mt-2 text-[10px] leading-5 text-slate-500">{stringValue(item.interpretation)}</p></div>)}</DetailSection>
      <DetailSection title="依赖与关联线索">{dependencies.length ? dependencies.map((item, index) => <div key={`${item.kind}:${index}`} className="rounded-xl border border-cyan/10 bg-cyan/[0.025] p-3"><div className="text-[10px] text-cyan">{stringValue(item.label)}</div><div className="mt-2 flex flex-wrap gap-1">{asStrings(item.artifact_paths).map((path) => <span key={path} className="rounded bg-black/20 px-2 py-1 font-mono text-[8px] text-slate-500">{path}</span>)}</div></div>) : <Unrecovered />}</DetailSection>
    </>}
    {node.node_kind === 'interface' && <DetailSection title="路由与执行绑定"><DetailGrid items={[
      ['HTTP 方法', stringValue(details.method)], ['路径状态', stringValue(details.path_status)],
      ['暴露状态', stringValue(details.exposure_status)], ['Handler', stringValue(details.handler_symbol)],
      ['Handler identity', stringValue(details.handler_identity)], ['组件路径', parent?.label ?? '未关联'],
    ]} /></DetailSection>}
    {node.node_kind === 'component' && <DetailSection title="组件归属"><DetailGrid items={[
      ['组件类型', stringValue(details.component_kind)], ['证据路径', stringValue(details.source_path)],
      ['归属依据', stringValue(details.ownership_basis)], ['接口数量', String(node.child_ids.length)],
    ]} /></DetailSection>}
    {node.node_kind === 'firmware' && <DetailSection title="发行身份"><DetailGrid items={[
      ['厂商', stringValue(details.vendor)], ['产品', stringValue(details.product)],
      ['型号', stringValue(details.device_model)], ['版本', stringValue(details.firmware_version)],
    ]} /></DetailSection>}
    <DetailSection title="原始证据位置">{evidence.length ? <>{evidence.map((item) => <div key={stringValue(item.evidence_id)} className="mb-2 rounded-xl border border-white/[0.06] p-3"><div className="font-mono text-[9px] text-cyan">{stringValue(item.artifact_path)} · {stringValue(item.locator)}</div><div className="mt-1 text-[9px] text-slate-600">{stringValue(item.capability)} · {stringValue(item.predicate)}</div></div>)}{Number(details.additional_evidence_count || 0) > 0 && <div className="text-[9px] text-slate-600">另有 {Number(details.additional_evidence_count)} 条证据，可在原始证据视图继续检查。</div>}</> : <Unrecovered />}</DetailSection>
    {stringValue(details.claim_boundary) && <div className="mt-5 rounded-xl border border-amber-300/10 bg-amber-300/[0.025] p-3 text-[9px] leading-5 text-slate-600"><ShieldQuestion size={11} className="mr-1.5 inline text-amber-300" />{stringValue(details.claim_boundary)}</div>}
  </article>
}

function DetailSection({ title, children }: { title: string; children: ReactNode }) {
  return <section className="mt-6"><div className="mb-3 flex items-center gap-2 text-[9px] uppercase tracking-[0.14em] text-slate-600"><GitBranch size={11} />{title}</div>{children}</section>
}

function DetailGrid({ items }: { items: Array<[string, string]> }) {
  return <div className="grid gap-2 sm:grid-cols-2">{items.map(([label, value]) => <div key={label} className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3"><div className="text-[8px] uppercase tracking-[0.1em] text-slate-700">{label}</div><div className="mt-1 break-all font-mono text-[9px] leading-4 text-slate-300">{value || '未恢复'}</div></div>)}</div>
}

function Unrecovered() { return <div className="rounded-xl border border-dashed border-white/[0.07] p-3 text-[10px] text-slate-600"><Box size={12} className="mr-2 inline" />当前确定性证据尚未恢复</div> }
function stringValue(value: unknown): string { return typeof value === 'string' ? value : value == null ? '' : String(value) }
function asStrings(value: unknown): string[] { return Array.isArray(value) ? value.map(String) : [] }
function asRecords(value: unknown): Array<Record<string, unknown>> { return Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => !!item && typeof item === 'object') : [] }
