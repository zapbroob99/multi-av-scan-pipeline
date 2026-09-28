import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { describe, it, expect } from 'vitest'
import { ListSearch, listQuery } from './list-search'

function Location() {
  return <output aria-label="location">{useLocation().search}</output>
}

function mount(entry: string) {
  render(<MemoryRouter initialEntries={[entry]}><Routes><Route path="/list" element={<>
    <ListSearch label="Search workers" placeholder="Name" /><Location /></>} /></Routes></MemoryRouter>)
}

describe('ListSearch', () => {
  it('starts every new search from the first page and clears back to the full list', async () => {
    mount('/list?after=node-20&keep=1')
    await userEvent.type(screen.getByRole('textbox', { name: 'Search workers' }), '  linux  {Enter}')
    expect(screen.getByLabelText('location')).toHaveTextContent('?keep=1&q=linux')
    await userEvent.click(screen.getByRole('button', { name: 'Clear' }))
    expect(screen.getByLabelText('location')).toHaveTextContent('?keep=1')
    expect(screen.queryByRole('button', { name: 'Clear' })).toBeNull()
  })

  it('builds list reads with the cursor and the query only when set', () => {
    expect(listQuery('', '').toString()).toBe('limit=20')
    expect(listQuery('7', 'drive').toString()).toBe('limit=20&after=7&q=drive')
  })
})
