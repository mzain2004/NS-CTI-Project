import type { RiskLevel } from './analysis'

export interface ReportMetadata {
  report_id: string
  analysis_id: string
  file_name: string
  sha256: string
  generated_at: string
  risk_level: RiskLevel
  analyst: string
}

export type ExportFormat = 'pdf' | 'json' | 'ioc_txt'

export interface ReportExport {
  report_id: string
  format: ExportFormat
  download_url: string
}

export interface ReportGenerateRequest {
  analysis_id: string
  analyst: string
  formats: ExportFormat[]
}

export interface ReportGenerateResponse {
  report_id: string
  metadata: ReportMetadata
  download_urls: Record<ExportFormat, string>
}
