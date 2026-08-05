import { describe, expect, it } from 'vitest'
import { formatCompactNumber, formatRelativeTime, severityTone } from './format'

describe('format helpers', () => {
  it('formats relative update time', () => {
    expect(
      formatRelativeTime('2026-08-05T11:00:00Z', new Date('2026-08-05T12:00:00Z')),
    ).toContain('1小时前')
  })

  it('formats compact counts and severity colors', () => {
    expect(formatCompactNumber(1200)).toMatch(/1[,.]?2?千|1200/)
    expect(severityTone('CRITICAL')).toContain('ff8a65')
  })
})
