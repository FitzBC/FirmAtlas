import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'
import type { InterfaceForceGraph } from '../types'
import { FirmwareInterfaceForceGraph } from './FirmwareInterfaceForceGraph'

const graph: InterfaceForceGraph = {
  schema_version: 'firmatlas.mapping.interface-force-graph/v1alpha1',
  catalog_id: 'catalog:ac9', firmware_artifact_sha256: '1'.repeat(64),
  root_node_id: 'root:ac9',
  summary: {
    component_count: 1, binary_component_count: 1, interface_count: 1,
    parameter_count: 1, native_only_interface_count: 0,
    unknown_parameter_type_count: 0, excluded_static_resource_interface_count: 0,
  },
  claim_boundary: '参数名称不用于猜测数据类型与约束。',
  nodes: [{
    node_id: 'root:ac9', node_kind: 'firmware', label: 'Tenda AC9 V15.03.05.19(6318)',
    parent_id: null, child_ids: ['component:httpd'], expandable: true, status: 'partial',
    details: { vendor: 'Tenda', device_model: 'AC9' },
  }, {
    node_id: 'component:httpd', node_kind: 'component', label: 'bin/httpd',
    parent_id: 'root:ac9', child_ids: ['interface:set-time'], expandable: true, status: 'observed',
    details: { component_kind: 'binary', ownership_basis: 'native registration source' },
  }, {
    node_id: 'interface:set-time', node_kind: 'interface', label: '/goform/SetTimeCfg',
    parent_id: 'component:httpd', child_ids: ['parameter:timezone'], expandable: true, status: 'supported',
    details: {
      method: 'POST', handler_symbol: 'formSetTimeCfg', handler_identity: 'bin/httpd@0x00071234',
      exposure_status: 'frontend_and_native', frontend_reference_observed: true,
    },
  }, {
    node_id: 'parameter:timezone', node_kind: 'parameter', label: 'timezone',
    parent_id: 'interface:set-time', child_ids: [], expandable: false, status: 'observed',
    details: {
      namespace: 'form', parameter_role: 'operation_selector', data_type: 'integer',
      data_type_basis: 'selector_domain', allowed_values: ['0', '8'],
      function_summary: '选择接口内部操作分支',
      constraints: [{ kind: 'selector_domain', status: 'observed', values: ['0', '8'], interpretation: '静态观察值域' }],
      dependencies: [{ kind: 'code_reference_assessment', status: 'external_clue_observed', label: 'external clue', artifact_paths: ['bin/httpd'], additional_artifact_count: 0 }],
      evidence_locations: [{ evidence_id: 'evidence:1', capability: 'mentions_parameter', predicate: 'mentions_parameter', artifact_path: 'bin/httpd', locator: 'virtual:0x712f0' }],
      claim_boundary: '类型只由 selector 值域归纳。',
    },
  }],
  edges: [{ edge_id: 'e:1', source_ref: 'root:ac9', target_ref: 'component:httpd', edge_kind: 'contains', label: '包含组件' },
    { edge_id: 'e:2', source_ref: 'component:httpd', target_ref: 'interface:set-time', edge_kind: 'exposes', label: '暴露接口' },
    { edge_id: 'e:3', source_ref: 'interface:set-time', target_ref: 'parameter:timezone', edge_kind: 'accepts', label: '接收参数' }],
}

const manyInterfaces = Array.from({ length: 60 }, (_, index) => ({
  node_id: `interface:${index}`, node_kind: 'interface' as const,
  label: `/goform/Operation${index}`, parent_id: 'component:httpd', child_ids: [],
  expandable: false, status: 'observed', details: {},
}))
const largeGraph: InterfaceForceGraph = {
  ...graph,
  summary: { ...graph.summary, interface_count: manyInterfaces.length, parameter_count: 0 },
  nodes: [
    { ...graph.nodes[0], child_ids: ['component:httpd'] },
    { ...graph.nodes[1], child_ids: manyInterfaces.map((node) => node.node_id) },
    ...manyInterfaces,
  ],
  edges: [
    graph.edges[0],
    ...manyInterfaces.map((node, index) => ({
      edge_id: `edge:${index}`, source_ref: 'component:httpd', target_ref: node.node_id,
      edge_kind: 'exposes' as const, label: '暴露接口',
    })),
  ],
}

afterEach(cleanup)

it('expands firmware to binary to interface to parameter and opens evidence details', () => {
  render(<FirmwareInterfaceForceGraph graph={graph} />)

  expect(screen.getByRole('button', { name: '选择节点 Tenda AC9 V15.03.05.19(6318)' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: '展开组件 bin/httpd' })).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: '展开接口 /goform/SetTimeCfg' })).not.toBeInTheDocument()

  fireEvent.click(screen.getByRole('button', { name: '展开组件 bin/httpd' }))
  fireEvent.click(screen.getByRole('button', { name: '展开接口 /goform/SetTimeCfg' }))
  fireEvent.click(screen.getByRole('button', { name: '选择参数 timezone' }))

  expect(screen.getByText('参数详情')).toBeInTheDocument()
  expect(screen.getByText('integer')).toBeInTheDocument()
  expect(screen.getByText('0 · 8')).toBeInTheDocument()
  expect(screen.getByText('formSetTimeCfg')).toBeInTheDocument()
  expect(screen.getByText('bin/httpd · virtual:0x712f0')).toBeInTheDocument()
  expect(screen.getByText('静态观察值域')).toBeInTheDocument()
})

it('resets the automatic force layout without losing expansion state', () => {
  render(<FirmwareInterfaceForceGraph graph={graph} />)
  fireEvent.click(screen.getByRole('button', { name: '重新自动布局' }))
  expect(screen.getByText('自动布局已重置')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: '展开组件 bin/httpd' })).toBeInTheDocument()
})

it('expands an expandable node when the user clicks its body', () => {
  render(<FirmwareInterfaceForceGraph graph={graph} />)

  fireEvent.click(screen.getByRole('button', { name: '选择节点 bin/httpd' }))

  expect(screen.getByRole('button', { name: '选择节点 /goform/SetTimeCfg' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: '折叠组件 bin/httpd' })).toBeInTheDocument()
})

it('keeps the expand control separate from the node drag surface', () => {
  render(<FirmwareInterfaceForceGraph graph={graph} />)
  const expand = screen.getByRole('button', { name: '展开组件 bin/httpd' })

  fireEvent.pointerDown(expand, { pointerId: 1, clientX: 220, clientY: 180 })
  fireEvent.pointerMove(expand, { pointerId: 1, clientX: 230, clientY: 184 })
  fireEvent.pointerUp(expand, { pointerId: 1, clientX: 230, clientY: 184 })
  fireEvent.click(expand)

  expect(screen.getByRole('button', { name: '选择节点 /goform/SetTimeCfg' })).toBeInTheDocument()
  expect(screen.queryByText('已拖动节点 bin/httpd')).not.toBeInTheDocument()
})

it('keeps the expanded firmware and component inside the initial large-graph viewport', () => {
  render(<FirmwareInterfaceForceGraph graph={largeGraph} />)

  fireEvent.click(screen.getByRole('button', { name: '选择节点 bin/httpd' }))

  const firmwareCard = screen.getByRole('button', { name: '选择节点 Tenda AC9 V15.03.05.19(6318)' }).closest('foreignObject')
  const componentCard = screen.getByRole('button', { name: '选择节点 bin/httpd' }).closest('foreignObject')
  expect(Number(firmwareCard?.getAttribute('y'))).toBeLessThan(500)
  expect(Number(componentCard?.getAttribute('y'))).toBeLessThan(500)
  expect(Number(firmwareCard?.getAttribute('x'))).toBeGreaterThanOrEqual(0)
  expect(Number(componentCard?.getAttribute('x'))).toBeGreaterThanOrEqual(0)
})

it('narrows a large graph to the matching branch while preserving ancestors', () => {
  render(<FirmwareInterfaceForceGraph graph={graph} />)
  fireEvent.change(screen.getByRole('textbox', { name: '搜索力导图节点' }), {
    target: { value: 'SetTimeCfg' },
  })

  expect(screen.getByRole('button', { name: '选择节点 /goform/SetTimeCfg' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: '选择节点 bin/httpd' })).toBeInTheDocument()
  expect(screen.getByText('可见 3 / 4 nodes · 2 edges')).toBeInTheDocument()
})

it('lets the user drag a node and explains the live mouse interactions', () => {
  render(<FirmwareInterfaceForceGraph graph={graph} />)
  const component = screen.getByRole('button', { name: '选择节点 bin/httpd' })

  fireEvent.pointerDown(component, { pointerId: 1, clientX: 220, clientY: 180 })
  fireEvent.pointerMove(component, { pointerId: 1, clientX: 360, clientY: 260 })
  fireEvent.pointerUp(component, { pointerId: 1, clientX: 360, clientY: 260 })
  fireEvent.click(component)

  expect(screen.getByRole('status')).toHaveTextContent('已拖动节点 bin/httpd')
  expect(screen.getByText('点击节点展开 / 折叠 · 拖拽移动 · 滚轮缩放 · 悬停高亮邻接关系')).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: '选择节点 /goform/SetTimeCfg' })).not.toBeInTheDocument()
})
