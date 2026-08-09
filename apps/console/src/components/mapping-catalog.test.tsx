import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { intelligenceApi } from '../api/client'
import type { MappingCandidate, MappingCandidateDetail, MappingCatalogSummary } from '../types'
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
  }],
  open_obligations: [],
  evidence_atoms: [{ evidence_id: 'ev:1', predicate: 'constructs', object_value: candidate.canonical_identity, capability: 'constructs_request', source_span: { artifact_path: candidate.source_path, locator: 'text:1' } }],
  coverage: [{ scope: 'webroot/**/*.js', producer_kind: 'frontend', producer: 'frontend-request-producer', status: 'completed' }],
}

afterEach(() => vi.restoreAllMocks())

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
  expect(screen.getByText('已验证 Native 绑定')).toBeInTheDocument()
  expect(screen.getByText('SetOnlineDevName')).toBeInTheDocument()
})
