import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { intelligenceApi } from '../api/client'
import type {
  MappingCandidate, MappingCandidateDetail, MappingCatalogSummary,
  MappingSnapshotDiff, PotentialHiddenInterfacePage,
} from '../types'
import { MappingCatalogWorkspace } from './MappingCatalogWorkspace'

const catalog: MappingCatalogSummary = {
  catalog_id: 'discovery-catalog:abc', schema_version: 'firmatlas.mapping.discovery-catalog/v1alpha1',
  firmware_artifact_sha256: '1'.repeat(64), source_inventory_sha256: '2'.repeat(64),
  coverage_status: 'partial', source_inventory_coverage_status: 'partial',
  scheduler_termination: 'fixed_point',
  published_at: '2026-08-09T00:00:00Z', candidate_count: 1, parameter_count: 2,
  association_count: 0, open_obligation_count: 0,
}
const candidate: MappingCandidate = {
  candidate_id: 'request:abc', candidate_kind: 'request_interface',
  canonical_identity: '/goform/SetOnlineDevName', claim_status: 'candidate',
  source_path: 'webroot/js/online.js', source_construct: 'jQuery.post',
  evidence_ids: ['ev:1'], attributes: [['method', 'POST']],
  parameter_count: 2, association_count: 0, open_obligation_count: 0,
}
const detail: MappingCandidateDetail = {
  catalog: {
    catalog_id: catalog.catalog_id,
    coverage_status: 'partial',
    source_inventory_coverage_status: 'partial',
    scheduler_termination: 'fixed_point',
  },
  candidate,
  parameters: [{ parameter_id: 'p:1', name: 'devName', namespace: 'form', literal_value: null, selector_values: [], is_operation_selector: false, source_construct: 'form_urlencoded' }],
  associations: [],
  related_candidates: [{
    ...candidate, candidate_id: 'native-binding:1', candidate_kind: 'native_route_binding',
    canonical_identity: 'SetOnlineDevName', claim_status: 'supported',
    source_path: 'bin/httpd', source_construct: 'elf.named-route-handler-pairs/v1:.routes',
  }, {
    ...candidate, candidate_id: 'ubus-binding:1', candidate_kind: 'ubus_backend_binding',
    canonical_identity: 'ubus://luci/getFeatures', claim_status: 'supported',
    source_path: 'usr/libexec/rpcd/luci', source_construct: 'static_plugin_dispatch',
    attributes: [['binding_status', 'static_plugin_dispatch'], ['parameter_names', 'detail']],
  }, {
    ...candidate, candidate_id: 'ubus-principal:1', candidate_kind: 'runtime_principal',
    canonical_identity: 'usr/libexec/rpcd/luci', claim_status: 'supported',
    source_path: 'usr/libexec/rpcd/luci', source_construct: 'rpcd_exec_plugin',
    attributes: [['principal_kind', 'rpcd_exec_plugin']],
  }, {
    ...candidate, candidate_id: 'ubus-grant:1', candidate_kind: 'ubus_access_grant',
    canonical_identity: 'ubus://luci/getFeatures', claim_status: 'supported',
    source_path: 'usr/share/rpcd/acl.d/luci-base.json', source_construct: 'rpcd_acl',
    attributes: [['access_mode', 'read'], ['policy_group', 'unauthenticated'], ['object_pattern', 'luci']],
  }],
  open_obligations: [{
    obligation_id: 'obligation:owner', target_ref: candidate.candidate_id, status: 'open',
    reason: 'No declared artifact scope statically binds this operation.',
    required_capability: 'resolve_ubus_runtime_owner', priority: 80,
    candidate_analyzers: ['rpcd-plugin-analyzer', 'ghidra-adapter'],
  }],
  evidence_atoms: [{ evidence_id: 'ev:1', predicate: 'constructs', object_value: candidate.canonical_identity, capability: 'constructs_request', source_span: { artifact_path: candidate.source_path, locator: 'text:1' } }],
  coverage: [{ scope: 'webroot/**/*.js', producer_kind: 'frontend', producer: 'frontend-request-producer', status: 'completed' }],
}
const hiddenPage: PotentialHiddenInterfacePage = {
  items: [{
    interface_id: 'potential-hidden-interface:1', catalog_id: catalog.catalog_id,
    firmware_artifact_sha256: catalog.firmware_artifact_sha256,
    operation_token: 'UploadFirmwareFile', attribution_id: 'set-difference:1',
    registration_artifact_path: 'www/cgi-bin/cstecgi.cgi',
    binding_ids: ['native-route-binding:1'],
    handler_identities: ['www/cgi-bin/cstecgi.cgi@0x00419e8c'],
    frontend_coverage_scopes: ['www/**/*.{js,html}'],
    frontend_coverage_complete: true, runtime_reachability_verified: false,
    interpretation: 'Native registration has no observed frontend reference.',
    open_obligation: 'Test hidden clients, direct requests, and dead registrations.',
    evidence_ids: ['ev:native'],
  }],
  total: 1, limit: 200, offset: 0,
  summary: {
    firmware_count: 1, handler_count: 1,
    eligible_firmware_count: 1, coverage_gap_firmware_count: 2,
  },
  distributions: {
    firmware: [{
      firmware_artifact_sha256: catalog.firmware_artifact_sha256,
      catalog_id: catalog.catalog_id, count: 1,
    }],
    artifact: [{ path: 'www/cgi-bin/cstecgi.cgi', count: 1 }],
  },
}
const targetCatalog: MappingCatalogSummary = {
  ...catalog,
  catalog_id: 'discovery-catalog:def',
  firmware_artifact_sha256: '3'.repeat(64),
  coverage_status: 'completed', source_inventory_coverage_status: 'completed',
  published_at: '2026-08-10T00:00:00Z', candidate_count: 2,
}
const snapshotDiff: MappingSnapshotDiff = {
  schema_version: 'firmatlas.mapping.snapshot-diff/v1alpha1',
  comparison_id: 'mapping-snapshot-diff:1',
  base: { catalog_id: catalog.catalog_id, firmware_artifact_sha256: catalog.firmware_artifact_sha256 },
  target: { catalog_id: targetCatalog.catalog_id, firmware_artifact_sha256: targetCatalog.firmware_artifact_sha256 },
  comparison_status: 'coverage_confounded', same_firmware_family_verified: false,
  summary: {
    added_candidate_count: 1, removed_candidate_count: 0, changed_candidate_count: 1,
    added_parameter_count: 0, removed_parameter_count: 0, changed_parameter_count: 0,
    discovered_hidden_interface_count: 1, resolved_hidden_interface_count: 0,
    changed_hidden_interface_count: 0, coverage_change_count: 1, total_change_count: 4,
  },
  changes: [{
    change_id: 'mapping-snapshot-change:1', category: 'candidate',
    stable_identity: 'request_interface|/goform/SetOnlineDevName',
    display_identity: '/goform/SetOnlineDevName', change_kind: 'changed',
    confidence: 'coverage_confounded', changed_fields: ['attributes'],
    base: { attributes: [['method', 'POST']] },
    target: { attributes: [['method', 'PUT']] },
    interpretation: 'observed structural difference may be caused by analysis coverage drift',
  }],
  diagnostics: [{
    code: 'firmware_family_unverified',
    message: 'catalogs do not carry a verified release-family relation',
  }],
}

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

it('navigates catalog, candidate and evidence levels without overlay drawers', async () => {
  vi.spyOn(intelligenceApi, 'mappingCatalogs').mockResolvedValue({ items: [catalog], total: 1, limit: 50, offset: 0 })
  const query = vi.spyOn(intelligenceApi, 'mappingCandidates').mockResolvedValue({ items: [candidate], total: 1, limit: 100, offset: 0 })
  vi.spyOn(intelligenceApi, 'mappingCandidate').mockResolvedValue(detail)

  render(<MappingCatalogWorkspace />)

  expect(await screen.findByText('/goform/SetOnlineDevName')).toBeInTheDocument()
  expect(screen.getAllByText('Inventory partial').length).toBeGreaterThan(0)
  fireEvent.click(screen.getByRole('button', { name: '请求接口' }))
  await waitFor(() => expect(query).toHaveBeenLastCalledWith(
    catalog.catalog_id, expect.objectContaining({ kind: 'request_interface' }), expect.any(AbortSignal),
  ))
  fireEvent.click(screen.getByRole('button', { name: '集合差异' }))
  await waitFor(() => expect(query).toHaveBeenLastCalledWith(
    catalog.catalog_id, expect.objectContaining({ kind: 'set_difference_attribution' }), expect.any(AbortSignal),
  ))
  fireEvent.click(screen.getByRole('button', { name: /查看候选/ }))
  expect(await screen.findByText('devName')).toBeInTheDocument()
  expect(screen.getByText('架构与分析属性')).toBeInTheDocument()
  expect(screen.getByText('method')).toBeInTheDocument()
  expect(screen.getByText('POST')).toBeInTheDocument()
  expect(screen.getByText('constructs_request')).toBeInTheDocument()
  expect(screen.getByText('后端执行与访问链')).toBeInTheDocument()
  expect(screen.getByText('SetOnlineDevName')).toBeInTheDocument()
  expect(screen.getByText('rpcd_exec_plugin')).toBeInTheDocument()
  expect(screen.getByText('read · unauthenticated')).toBeInTheDocument()
  expect(screen.getByText('未决分析义务')).toBeInTheDocument()
  expect(screen.getByText('resolve_ubus_runtime_owner')).toBeInTheDocument()
})

it('shows potential hidden interfaces as a coverage-gated cross-firmware view', async () => {
  vi.spyOn(intelligenceApi, 'mappingCatalogs').mockResolvedValue({
    items: [catalog], total: 1, limit: 50, offset: 0,
  })
  vi.spyOn(intelligenceApi, 'mappingCandidates').mockResolvedValue({
    items: [candidate], total: 1, limit: 100, offset: 0,
  })
  const hidden = vi.spyOn(intelligenceApi, 'potentialHiddenInterfaces')
    .mockResolvedValue(hiddenPage)

  render(<MappingCatalogWorkspace />)
  fireEvent.click(await screen.findByRole('button', { name: '潜在隐藏接口' }))

  expect(await screen.findByText('UploadFirmwareFile')).toBeInTheDocument()
  expect(screen.getByText('覆盖合格固件')).toBeInTheDocument()
  expect(screen.getByText('固件信号分布')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: /查看潜在隐藏接口/ }))
  expect(screen.getByText('不是后门结论')).toBeInTheDocument()
  expect(screen.getByText('www/cgi-bin/cstecgi.cgi@0x00419e8c')).toBeInTheDocument()
  expect(hidden).toHaveBeenCalled()
})

it('compares two mapping snapshots without hiding coverage confounding', async () => {
  vi.spyOn(intelligenceApi, 'mappingCatalogs').mockResolvedValue({
    items: [targetCatalog, catalog], total: 2, limit: 50, offset: 0,
  })
  vi.spyOn(intelligenceApi, 'mappingCandidates').mockResolvedValue({
    items: [candidate], total: 1, limit: 100, offset: 0,
  })
  const compare = vi.spyOn(intelligenceApi, 'compareMappingCatalogs')
    .mockResolvedValue(snapshotDiff)

  render(<MappingCatalogWorkspace />)
  fireEvent.click(await screen.findByRole('button', { name: '版本对比' }))

  expect(await screen.findByText('覆盖不可直接比较')).toBeInTheDocument()
  expect(screen.getByText('新增结构')).toBeInTheDocument()
  expect(screen.getByText('潜在隐藏新增')).toBeInTheDocument()
  expect(screen.getByRole('textbox', { name: '搜索版本差异' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: '接口 / 候选' })).toBeInTheDocument()
  expect(screen.getByText('/goform/SetOnlineDevName')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: /查看版本差异/ }))
  expect(screen.getAllByText('attributes').length).toBeGreaterThan(0)
  expect(screen.getByText(/不能断言同型号版本谱系/)).toBeInTheDocument()
  fireEvent.change(screen.getByRole('textbox', { name: '搜索版本差异' }), {
    target: { value: 'ubus://' },
  })
  expect(screen.getByText('当前筛选范围没有观察到结构差异')).toBeInTheDocument()
  expect(compare).toHaveBeenCalledWith(
    catalog.catalog_id, targetCatalog.catalog_id, expect.any(AbortSignal),
  )
})
