import { fireEvent, render, screen } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { PaginationControls } from './PaginationControls'

it('jumps directly to a validated page number', () => {
  const onPage = vi.fn()
  render(<PaginationControls page={2} pages={8} total={156} hasPrevious hasNext onPage={onPage} />)

  fireEvent.change(screen.getByLabelText('跳转页码'), { target: { value: '7' } })
  fireEvent.submit(screen.getByRole('form', { name: '跳转分页' }))

  expect(onPage).toHaveBeenCalledWith(7)
})
