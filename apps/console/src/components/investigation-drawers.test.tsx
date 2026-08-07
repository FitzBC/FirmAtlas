import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'

import { intelligenceApi } from '../api/client'
import type { FirmwareCandidateDetail, Vulnerability } from '../types'
import { FirmwareCandidateDrawer } from './FirmwareCatalogWorkspace'
import { VulnerabilityDetail } from './VulnerabilityDetail'

const firmware: FirmwareCandidateDetail = {
  candidate_id: 'fixture:one', source_id: 'fixture', external_id: 'ONE',
  vendor: 'D-Link', product: 'DIR-823G', model: 'DIR-823G', firmware_version: '1.0.2B05',
  filename: 'DIR823G_1.0.2B05.bin', download_url: 'https://example.test/firmware.bin',
  download_host: 'example.test', source_page_url: 'https://example.test/release',
  evidence_url: 'https://example.test/catalog', url_status: 'listed', download_kind: 'direct',
  notes: '', source_name: 'Fixture', source_type: 'official', trust_level: 'primary',
  vulnerability_count: 1, vulnerability_identifiers: ['CVE-2025-1001'],
  version_identities: [{ raw: '1.0.2B05', normalized: '1.0.2b05', source: 'declared', confidence: 'high' }],
  source_base_url: 'https://example.test', source_access_notes: '',
  vulnerabilities: [{
    candidate_id: 'fixture:one', vulnerability_identifier: 'CVE-2025-1001',
    relationship: 'affected_release_candidate', confidence: 'high', evidence_url: 'https://nvd.test', notes: '',
    title: 'Router vulnerability', vulnerability_vendor: 'D-Link', vulnerability_product: 'DIR-823G',
    severity: 'HIGH', cvss_score: 8.8, association_origin: 'derived', match_method: 'exact_version',
    match_score: 98, candidate_version: '1.0.2B05', affected_constraint: '1.0.2b05', matched_criteria: 'cpe:2.3:o:dlink:dir-823g_firmware:1.0.2b05:*:*:*:*:*:*:*',
  }],
}

const vulnerability = {
  identifier: 'CVE-2025-1001', title: 'Router vulnerability', summary: 'Full description',
  published_at: '2025-01-01T00:00:00Z', modified_at: '2025-01-02T00:00:00Z',
  vendor: 'D-Link', product: 'DIR-823G firmware', severity: 'HIGH', cvss_score: 8.8,
  cvss_vector: null, cvss_version: '3.1', impact_score: null, exploitability_score: null,
  attack_vector: 'NETWORK', attack_complexity: 'LOW', privileges_required: 'NONE',
  user_interaction: 'NONE', scope: 'UNCHANGED', cvss_metrics: [], aliases: [], cwes: [], cpes: [],
  references: [], reference_details: [], exploit_references: [], has_exploit: false, cwe_details: [],
  affected_products: [], sources: ['NVD'], kev: false, kev_date_added: null, kev_due_date: null,
  ransomware_use: null, required_action: null, relevance_score: 90, relevance_level: 'strong',
  relevance_signals: [], policy_version: 'test', is_firmware_related: true,
  semantic_interface_count: 0, semantic_parameter_count: 0,
} as Vulnerability

afterEach(() => vi.restoreAllMocks())

it('returns one drawer level at a time and only the top layer handles Escape', () => {
  const onClose = vi.fn()
  const { rerender } = render(
    <FirmwareCandidateDrawer detail={firmware} onClose={onClose} onOpenVulnerability={vi.fn()} parentLabel="CVE-2025-1001" isTop={false} stackOffset={1} />,
  )

  expect(screen.getByRole('button', { name: '返回上一级' })).toBeInTheDocument()
  expect(screen.getByText('返回 CVE-2025-1001')).toBeInTheDocument()
  fireEvent.keyDown(window, { key: 'Escape' })
  expect(onClose).not.toHaveBeenCalled()

  rerender(<FirmwareCandidateDrawer detail={firmware} onClose={onClose} onOpenVulnerability={vi.fn()} parentLabel="CVE-2025-1001" isTop stackOffset={0} />)
  fireEvent.keyDown(window, { key: 'Escape' })
  expect(onClose).toHaveBeenCalledTimes(1)
})

it('opens an exact associated firmware as the next investigation layer', async () => {
  vi.spyOn(intelligenceApi, 'semanticAnalysis').mockResolvedValue(null)
  vi.spyOn(intelligenceApi, 'firmwareSamplesForVulnerability').mockResolvedValue({
    identifier: vulnerability.identifier, items: [firmware], total: 1,
  })
  const onOpenFirmware = vi.fn()

  render(<VulnerabilityDetail vulnerability={vulnerability} onClose={vi.fn()} onOpenFirmware={onOpenFirmware} parentLabel="D-Link DIR-823G" />)

  const sample = await screen.findByRole('button', { name: /D-Link · DIR-823G/ })
  fireEvent.click(sample)
  expect(onOpenFirmware).toHaveBeenCalledWith(firmware.candidate_id)
  expect(screen.getByText('返回 D-Link DIR-823G')).toBeInTheDocument()
  await waitFor(() => expect(intelligenceApi.firmwareSamplesForVulnerability).toHaveBeenCalled())
})
