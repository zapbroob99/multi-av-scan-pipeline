import type { components, paths } from './api.generated'

type Schemas = components['schemas']
export type Session = Schemas['SessionPayload']
export type Health = Schemas['HealthPayload']
export type ConfigField = Schemas['FieldPayload']
export type Adapter = Schemas['AdapterPayload']
export type Engine = Schemas['EnginePayload']
export type Inventory = Schemas['InventoryPayload']
export type Rule = Schemas['RulePayload']
export type SubmissionOptions = Schemas['SubmissionOptions']
export type SubmissionAccepted = Schemas['SubmissionAccepted']
export type ReportEngine = Schemas['EngineSummary']
export type ScanReport = Schemas['ScanReport']
export type TechnicalDetails = Schemas['TechnicalDetails']
export type ArchiveChild = Schemas['ArchiveChild']
export type ArchivePage = Schemas['ArchivePage']
export type BatchPage = Schemas['BatchPage']
export type BatchScan = Schemas['BatchScan']
export type ScanPreview = Schemas['ScanPreview']
export type ScanPage = Schemas['ScanPage']
export type DashboardSummary = Schemas['DashboardSummary']

type Method = 'get' | 'post' | 'put' | 'delete'
type Route = keyof paths
type Methods<P extends Route> = { [M in Method]: NonNullable<paths[P][M]> extends never ? never : M }[Method]
type Operation<P extends Route, M extends Methods<P>> = NonNullable<paths[P][M]>
type PathOptions<O> = O extends { parameters: { path: infer P } } ? { params: P } : { params?: never }
type BodyOptions<O> = O extends { requestBody: { content: infer C } }
  ? C extends { 'application/json': infer B } ? { body: B }
    : C extends { 'multipart/form-data': unknown } ? { body: FormData } : never
  : { body?: never }
type JsonResult<R> = R extends { content: { 'application/json': infer B } } ? B : void
type Result<O> = O extends { responses: infer R } ? JsonResult<R[Extract<keyof R, 200 | 201 | 202 | 204>]> : never
type Options<P extends Route, M extends Methods<P>> = PathOptions<Operation<P, M>> & BodyOptions<Operation<P, M>>
  & { signal?: AbortSignal; query?: URLSearchParams }
  & (M extends 'get' ? { csrf?: never } : P extends '/api/ui/v1/session/login' ? { csrf?: never } : { csrf: string })

// Route/method/body/result types come from OpenAPI, not caller-supplied DTO assertions.
// Query string values and multipart fields remain server-validated at runtime.
export function request<P extends Route, M extends Methods<P>>(route: P, method: M, options: Options<NoInfer<P>, NoInfer<M>>): Promise<Result<Operation<P, M>>> {
  let path: string = route.slice('/api/ui/v1'.length)
  for (const [name, value] of Object.entries(options.params || {})) path = path.replace(`{${name}}`, encodeURIComponent(String(value)))
  if (/\{[^}]+\}/.test(path)) throw new Error('Missing API path parameter.')
  if (options.query?.size) path += `?${options.query}`
  return api(path, { method: method.toUpperCase(), body: options.body, csrf: options.csrf, signal: options.signal })
}

export class ApiError extends Error { constructor(public status: number, message: string) { super(message) } }

async function api<T>(path: string, options: { method?: string; body?: unknown; csrf?: string; signal?: AbortSignal } = {}): Promise<T> {
  const multipart = options.body instanceof FormData
  const response = await fetch(`/api/ui/v1${path}`, {
    method: options.method || 'GET', credentials: 'same-origin', cache: 'no-store', signal: options.signal,
    headers: { 'Accept': 'application/json', 'X-MASP-UI': '1',
      ...(options.body !== undefined && !multipart ? { 'Content-Type': 'application/json' } : {}),
      ...(options.csrf ? { 'X-CSRF-Token': options.csrf } : {}) },
    body: multipart ? options.body as FormData : options.body !== undefined ? JSON.stringify(options.body) : undefined,
  })
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}))
    if (response.status === 401 && path !== '/session' && path !== '/session/login') window.dispatchEvent(new Event('masp-session-expired'))
    throw new ApiError(response.status, typeof payload.detail === 'string' ? payload.detail : `Request failed (${response.status}).`)
  }
  return response.status === 204 ? undefined as T : response.json()
}

export function pollInterval(inventory?: Inventory) {
  return inventory?.engines.some(e => e.enabled && ['pending', 'running'].includes(e.health.state)) ? 3000 : 30000
}
