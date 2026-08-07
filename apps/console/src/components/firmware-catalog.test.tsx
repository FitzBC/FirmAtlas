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
  download_host: 'raw.example',
  source_page_url: 'https://example/benchmark', evidence_url: 'https://example/devices',
  url_status: 'listed', download_kind: 'direct', notes: '', source_name: 'FirmEmuHub',
  source_type: 'benchmark', trust_level: 'high', vulnerability_count: 1,
  vulnerability_identifiers: ['CVE-2017-13772'], version_link_count: 1,
  strongest_match_method: 'exact_version',
  version_identities: [{ raw: '3.16.9', normalized: '3.16.9', source: 'filename', confidence: 'medium' }],
}

afterEach(() => vi.restoreAllMocks())

it('searches sample metadata and opens a stackable firmware detail', async () => {
  vi.spyOn(intelligenceApi, 'firmwareOverview').mockResolvedValue({
    counts: { source_count: 18, official_source_count: 12, download_host_count: 34, candidate_count: 100, linked_candidate_count: 15, vulnerability_lead_count: 95 },
    vendors: [{ label: 'TP-Link', value: 50 }], sources: [], hosts: [{ label: 'raw.example', value: 100 }],
  })
  vi.spyOn(intelligenceApi, 'firmwareSources').mockResolvedValue({
    items: [{ source_id: 'firmemuhub', name: 'FirmEmuHub', source_type: 'benchmark', base_url: 'https://example', vendor: null, trust_level: 'high', access_notes: '', evidence_url: 'https://example', candidate_count: 100, vulnerability_count: 95 }],
  })
  const list = vi.spyOn(intelligenceApi, 'firmwareCandidates').mockResolvedValue({
    items: [candidate], total: 1, limit: 30, offset: 0, page: 1, pages: 1,
    has_previous: false, has_next: false,
  })
  const onOpenFirmware = vi.fn()

  render(<FirmwareCatalogWorkspace onOpenFirmware={onOpenFirmware} />)

  expect(await screen.findByText(/TP-Link · TL-WR940N/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: /版本级命中/ }))
  await waitFor(() => expect(list).toHaveBeenLastCalledWith(
    expect.objectContaining({ match: 'version' }), 1, expect.any(AbortSignal),
  ))
  fireEvent.click(screen.getByRole('button', { name: /raw.example.*100/ }))
  await waitFor(() => expect(list).toHaveBeenLastCalledWith(
    expect.objectContaining({ host: 'raw.example' }), 1, expect.any(AbortSignal),
  ))
  fireEvent.change(screen.getByPlaceholderText('搜索 CVE、厂商、型号、版本或文件名…'), { target: { value: 'CVE-2017-13772' } })
  await waitFor(() => expect(list).toHaveBeenLastCalledWith(
    expect.objectContaining({ query: 'CVE-2017-13772' }), 1, expect.any(AbortSignal),
  ))
  fireEvent.click(screen.getByRole('button', { name: /TP-Link · TL-WR940N/ }))
  expect(onOpenFirmware).toHaveBeenCalledWith(candidate.candidate_id)
})
