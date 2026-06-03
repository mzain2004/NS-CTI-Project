import type {
  AnalysisResult,
  BlockRequest,
  BlockResponse,
  CowrieSample,
  CowrieSession,
  VirusTotalResult,
  WazuhAlert,
} from '@shared/types'

export const API_URL = 'http://167.172.85.62:8000'

export interface ApiHealth {
  status?: string
}

export interface ReportListItem {
  report_id: string
  file_name?: string
  sha256?: string
  pdf_url?: string
  json_url?: string
  ioc_url?: string
}

export interface ReportGenerateResult {
  report_id: string
  pdf_url?: string
  json_url?: string
  ioc_url?: string
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
    cache: 'no-store',
  })

  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`)
  }

  return (await response.json()) as T
}

export async function analyzeFile(file: File): Promise<AnalysisResult> {
  const formData = new FormData()
  formData.append('file', file)

  const response = await fetch(`${API_URL}/api/analyze`, {
    method: 'POST',
    body: formData,
    cache: 'no-store',
  })

  if (!response.ok) {
    throw new Error(`Analyze failed: ${response.status}`)
  }

  return (await response.json()) as AnalysisResult
}

export function getAnalysisById(id: string): Promise<AnalysisResult> {
  return request<AnalysisResult>(`/api/analyze/${id}`)
}

export function getCowrieLogs(): Promise<CowrieSession[]> {
  return request<CowrieSession[]>('/api/cowrie/logs')
}

export function getCowrieSamples(): Promise<CowrieSample[]> {
  return request<CowrieSample[]>('/api/cowrie/samples')
}

export function getWazuhAlerts(): Promise<WazuhAlert[]> {
  return request<WazuhAlert[]>('/api/wazuh/alerts')
}

export function getApiHealth(): Promise<ApiHealth> {
  return request<ApiHealth>('/api/health')
}

export async function listReports(): Promise<ReportListItem[]> {
  const payload = await request<unknown>('/api/report/list')
  return Array.isArray(payload) ? (payload as ReportListItem[]) : []
}

export function getVirusTotal(hash: string): Promise<VirusTotalResult> {
  return request<VirusTotalResult>(`/api/virustotal/${hash}`)
}

export function blockPfSense(payload: BlockRequest): Promise<BlockResponse> {
  return request<BlockResponse>('/api/pfsense/block', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function generateReport(analysisId: string, analyst: string): Promise<ReportGenerateResult> {
  return request<ReportGenerateResult>('/api/report/generate', {
    method: 'POST',
    body: JSON.stringify({ analysis_id: analysisId, analyst, formats: ['pdf', 'json', 'ioc_txt'] }),
  })
}
