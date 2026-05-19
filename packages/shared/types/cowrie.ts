export interface CowrieSession {
  session_id: string
  timestamp: string
  src_ip: string
  src_port: number
  dst_port: number
  protocol: string
  username: string | null
  password: string | null
  commands: string[]
  duration_seconds: number
  files_downloaded: string[]
  country: string | null
}

export interface CowrieSample {
  sha256: string
  filename: string
  size: number
  downloaded_at: string
  src_ip: string
  url: string | null
  mime_type: string | null
  analyzed: boolean
  analysis_id: string | null
}
