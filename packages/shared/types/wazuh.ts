export type WazuhSeverity = 'low' | 'medium' | 'high' | 'critical'

export interface WazuhAlert {
  alert_id: string
  timestamp: string
  rule_id: string
  rule_description: string
  rule_level: number        // 0-15 Wazuh scale
  severity: WazuhSeverity
  agent_id: string
  agent_name: string
  src_ip: string | null
  dst_ip: string | null
  mitre_technique: string | null
  mitre_tactic: string | null
  full_log: string
  groups: string[]
}
