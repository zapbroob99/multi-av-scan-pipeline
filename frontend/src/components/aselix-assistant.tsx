import { useEffect, useRef, useState, type FormEvent } from 'react'
import { request } from '../lib/api'
import { Button } from './ui/button'

type Turn = { question: string; answer: string }
type Props = { csrf: string; scanId?: number; automation?: boolean }

export default function AselixAssistant({ csrf, scanId, automation }: Props) {
  const [turns, setTurns] = useState<Turn[]>([])
  const [question, setQuestion] = useState(scanId ? 'Bu taramanın sonucunu ve motor kapsamını açıklar mısın?' : '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const active = useRef<AbortController | null>(null)
  useEffect(() => () => active.current?.abort(), [])

  async function send(event: FormEvent) {
    event.preventDefault()
    const prompt = question.trim()
    if (!prompt || active.current) return
    const controller = new AbortController()
    active.current = controller
    setBusy(true)
    setError('')
    try {
      const options = { csrf, signal: controller.signal, body: { question: prompt, history: turns.slice(-3) } }
      const result = scanId === undefined
        ? await request('/api/ui/v1/assistant/chat', 'post', options)
        : await request(automation ? '/api/ui/v1/api-ledger/scans/{scan_id}/assistant' : '/api/ui/v1/scans/{scan_id}/assistant',
          'post', { ...options, params: { scan_id: scanId } })
      if (!controller.signal.aborted) {
        setTurns(previous => [...previous.slice(-2), { question: prompt, answer: result.answer }])
        setQuestion('')
      }
    } catch (err) {
      if (!controller.signal.aborted) setError((err as Error).message)
    } finally {
      active.current = null
      if (!controller.signal.aborted) setBusy(false)
    }
  }
  return <section className="submission-card" aria-label="Aselix conversation">
    <p className="muted">{scanId
      ? 'Send your question and a summary of the decision, risk and engine coverage to Aselix. The MASP report holds the official decision.'
      : 'Ask your internal Aselix service about MASP. Only your conversation is sent.'} Up to three prior exchanges accompany each question.</p>
    {turns.map((turn, index) => <div key={index}><p><strong>{turn.question}</strong></p>
      <p className="assistant-answer">{turn.answer}</p></div>)}
    <form onSubmit={send}>
      <label>Question for Aselix<textarea value={question} onChange={event => setQuestion(event.target.value)}
        rows={3} maxLength={1500} disabled={busy} required /></label>
      <div className="report-actions"><Button disabled={busy || !question.trim()}>Send to Aselix</Button>
        {turns.length > 0 && <Button type="button" variant="secondary" disabled={busy}
          onClick={() => { setTurns([]); setQuestion(''); setError('') }}>Clear conversation</Button>}</div>
    </form>
    {busy && <p role="status">Waiting for Aselix…</p>}
    {error && <p className="error" role="alert">{error}</p>}
  </section>
}
