// Compile-time regression gates. This function is never invoked or bundled.
import { request, type Session, type Health } from './api'

export async function contractTypeAssertions() {
  const session: Session = await request('/api/ui/v1/session', 'get', {})
  const health: Health = await request('/api/ui/v1/engines/{instance_id}/checks', 'post', { params: { instance_id: 1 }, csrf: session.csrf_token })
  const fullExport = await request('/api/ui/v1/scans/{scan_id}/export', 'get', { params: { scan_id: 1 }, query: new URLSearchParams({ format: 'json' }) })
  const batch = await request('/api/ui/v1/batches/{batch_id}', 'get', { params: { batch_id: 1 }, query: new URLSearchParams({ limit: '20' }) })
  const bulk = await request('/api/ui/v1/scans', 'delete', { csrf: session.csrf_token,
    body: { scans: [{ scan_id: 1, attempt: 0, job_revision: 0 }] } })
  const deleted: void = await request('/api/ui/v1/engines/{instance_id}', 'delete', { params: { instance_id: 1 }, csrf: session.csrf_token })
  void health; void fullExport.content; void batch.items; void bulk.deleted_ids; void deleted
  // @ts-expect-error Unknown endpoint must not compile.
  request('/api/ui/v1/unknown', 'get', {})
  // @ts-expect-error Wrong HTTP method must not compile.
  request('/api/ui/v1/session', 'delete', { csrf: 'token' })
  // @ts-expect-error JSON body is required.
  request('/api/ui/v1/session/login', 'post', {})
  // @ts-expect-error Required password cannot be omitted.
  request('/api/ui/v1/session/login', 'post', { body: { username: 'analyst' } })
  // @ts-expect-error Writes must supply CSRF.
  request('/api/ui/v1/engines/{instance_id}/checks', 'post', { params: { instance_id: 1 } })
  // @ts-expect-error Path ID is required.
  request('/api/ui/v1/scans/{scan_id}', 'get', {})
  // @ts-expect-error Wrong path parameter type.
  request('/api/ui/v1/scans/{scan_id}', 'get', { params: { scan_id: 'one' } })
  // @ts-expect-error Boolean is not a string.
  request('/api/ui/v1/engines/{instance_id}/enabled', 'put', { params: { instance_id: 1 }, csrf: 'token', body: { enabled: 'true' } })
  // @ts-expect-error Extra JSON properties must not compile.
  request('/api/ui/v1/engines/{instance_id}/enabled', 'put', { params: { instance_id: 1 }, csrf: 'token', body: { enabled: true, command: 'no' } })
  // @ts-expect-error GET has no body.
  request('/api/ui/v1/session', 'get', { body: {} })
  // @ts-expect-error A multipart endpoint cannot accept a JSON sample.
  request('/api/ui/v1/scans', 'post', { csrf: 'token', body: { sample: 'abc' } })
  // @ts-expect-error Cannot assert an unrelated response shape.
  const wrong: Session = await request('/api/ui/v1/engines', 'get', {})
  void wrong
}
