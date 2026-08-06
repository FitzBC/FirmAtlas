import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'

import { intelligenceApi } from '../api/client'
import type { FirmwareCandidate } from '../types'
import { FirmwareCatalogWorkspace } from './FirmwareCatalogWorkspace'

const candidate: FirmwareCandidate = {
  candidate_id: 'firmemuhub:BM-2024-00001', source_id: 'firmemuhub',
  external_id: 'BM-2024-00001', vendor: 'TP-Link', product: 'TL-WR940N',
  model: 'TL-WR940N', firmware_version: 'V4', filename: 'wr940nv4.bin',
  download_url: 'https://raw.example/wr940nv4.bin',
  source_page_url: 'https://example/benchmark', evidence_url: 'https://example/devices',
  url_status: 'listed', download_kind: 'direct', notes: '', source_name: 'FirmEmuHub',
  source_type: 'benchmark', trust_level: 'high', vulnerability_count: 1,
  vulnerability_identifiers: ['CVE-2017-13772'],
}

afterEach(() => vi.restoreAllMocks())

it('searches sample metadata and follows the sample-to-vulnerability relationship', async () => {
  vi.spyOn(intelligenceApi, 'firmwareOverview').mockResolvedValue({
    counts: { source_count: 18, official_source_count: 12, candidate_count: 100, linked_candidate_count: 15, vulnerability_lead_count: 95 },
    vendors: [{ label: 'TP-Link', value: 50 }], sources: [],
  })
  vi.spyOn(intelligenceApi, 'firmwareSources').mockResolvedValue({
    items: [{ source_id: 'firmemuhub', name: 'FirmEmuHub', source_type: 'benchmark', base_url: 'https://example', vendor: null, trust_level: 'high', access_notes: '', evidence_url: 'https://example', candidate_count: 100, vulnerability_count: 95 }],
  })
  const list = vi.spyOn(intelligenceApi, 'firmwareCandidates').mockResolvedValue({
    items: [candidate], total: 1, limit: 30, offset: 0, page: 1, pages: 1,
    has_previous: false, has_next: false,
  })
  vi.spyOn(intelligenceApi, 'firmwareCandidate').mockResolvedValue({
    ...candidate, source_base_url: 'https://example', source_access_notes: '',
    vulnerabilities: [{ candidate_id: candidate.candidate_id, vulnerability_identifier: 'CVE-2017-13772', relationship: 'reproduced_on', confidence: 'high', evidence_url: 'https://example/detail', notes: '', title: 'Router vulnerability', vulnerability_vendor: 'TP-Link', vulnerability_product: 'TL-WR940N', severity: 'HIGH', cvss_score: 8.8 }],
  })
  const onOpenVulnerability = vi.fn()

  render(<FirmwareCatalogWorkspace onOpenVulnerability={onOpenVulnerability} />)

  expect(await screen.findByText(/TP-Link · TL-WR940N/)).toBeInTheDocument()
  fireEvent.change(screen.getByPlaceholderText('搜索 CVE、厂商、型号、版本或文件名…'), { target: { value: 'CVE-2017-13772' } })
  await waitFor(() => expect(list).toHaveBeenLastCalledWith(
    expect.objectContaining({ query: 'CVE-2017-13772' }), 1, expect.any(AbortSignal),
  ))
  fireEvent.click(screen.getByRole('button', { name: /TP-Link · TL-WR940N/ }))
  fireEvent.click(await screen.findByRole('button', { name: /CVE-2017-13772/ }))
  expect(onOpenVulnerability).toHaveBeenCalledWith('CVE-2017-13772')
})
