import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { RadarPanel } from './RadarPanel'
import { VulnerabilityFeed } from './VulnerabilityFeed'
import type { IntelligenceFilters, Overview } from '../types'

const filters: IntelligenceFilters = {
  query: '', vendor: '', severity: '', relevance: 'firmware', kevOnly: false, exploitOnly: false,
}

const vendors = [
  { label: 'Cisco', value: 1285 },
  { label: 'D-Link', value: 785 },
]

it('applies an exact vendor filter from the common-vendor tags', () => {
  const onFiltersChange = vi.fn()
  render(
    <VulnerabilityFeed
      page={{ items: [], total: 0, limit: 50, offset: 0, page: 1, pages: 0, has_previous: false, has_next: false }}
      filters={filters}
      vendors={vendors}
      loading={false}
      filtering={false}
      onFiltersChange={onFiltersChange}
      onSelect={vi.fn()}
      onPageChange={vi.fn()}
    />,
  )

  fireEvent.click(screen.getByRole('button', { name: /Cisco/ }))
  expect(onFiltersChange).toHaveBeenCalledWith({ ...filters, vendor: 'Cisco' })
})

it('requests the next server page instead of slicing records in the browser', () => {
  const onPageChange = vi.fn()
  render(
    <VulnerabilityFeed
      page={{ items: [], total: 120, limit: 50, offset: 0, page: 1, pages: 3, has_previous: false, has_next: true }}
      filters={filters}
      vendors={vendors}
      loading={false}
      filtering={false}
      onFiltersChange={vi.fn()}
      onSelect={vi.fn()}
      onPageChange={onPageChange}
    />,
  )

  fireEvent.click(screen.getByRole('button', { name: /下一页/ }))
  expect(onPageChange).toHaveBeenCalledWith(2)
})

describe('vendor radar', () => {
  it('links a radar signal to the vendor filter', () => {
    const onVendorSelect = vi.fn()
    const overview = {
      counts: { relevant: 20700, critical: 2700, kev: 180, exploit: 4300 },
      last_updated: null,
      levels: [],
      vendors,
      recent: [],
    } satisfies Overview

    render(
      <RadarPanel
        overview={overview}
        latestSync={null}
        activeVendor=""
        onVendorSelect={onVendorSelect}
      />,
    )

    fireEvent.click(screen.getByRole('button', { name: '筛选 Cisco，1285 条漏洞' }))
    expect(onVendorSelect).toHaveBeenCalledWith('Cisco')
  })
})
