export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export interface PESection {
  name: string
  virtual_size: number
  raw_size: number
  entropy: number
  md5: string
  suspicious: boolean // entropy > 7.2 or known packer name
}

export interface ImportedFunction {
  dll: string
  function: string
  suspicious: boolean // matches known suspicious API list
}

export interface YaraHit {
  rule_name: string
  description: string
  tags: string[]
  matched_strings: string[]
}

export interface StaticAnalysis {
  file_name: string
  file_size: number
  file_type: string
  md5: string
  sha1: string
  sha256: string
  pe_sections: PESection[]
  imports: ImportedFunction[]
  strings_extracted: string[]
  yara_hits: YaraHit[]
  is_packed: boolean
  compile_timestamp: string | null
  entry_point: string
}

export interface MitreTechnique {
  technique_id: string   // e.g. T1059
  technique_name: string
  tactic: string         // e.g. Execution
  description: string
  confidence: number     // 0-100
}

export interface IoCs {
  ips: string[]
  domains: string[]
  urls: string[]
  hashes: string[]
  registry_keys: string[]
  file_paths: string[]
  mutexes: string[]
}

export interface GroqAnalysis {
  malware_family: string
  confidence: number
  behavior_summary: string
  mitre_techniques: MitreTechnique[]
  iocs: IoCs
  risk_level: RiskLevel
  recommended_actions: string[]
  analyst_notes: string
  raw_response: string
}

export interface VirusTotalResult {
  detection_ratio: string     // "47/72"
  detections: number
  total_engines: number
  malicious: number
  suspicious: number
  undetected: number
  engine_hits: { engine: string; result: string }[]
  first_seen: string | null
  last_seen: string | null
  community_score: number
  vt_link: string
  family_names: string[]
}

export interface AnalysisResult {
  analysis_id: string
  status: 'pending' | 'running' | 'complete' | 'error'
  created_at: string
  file_name: string
  static_analysis: StaticAnalysis | null
  groq_analysis: GroqAnalysis | null
  virustotal: VirusTotalResult | null
  error: string | null
}
