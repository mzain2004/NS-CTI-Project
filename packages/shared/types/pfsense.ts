export type RuleAction = 'block' | 'pass' | 'reject'
export type RuleProtocol = 'tcp' | 'udp' | 'tcp/udp' | 'icmp' | 'any'

export interface PfSenseRule {
  rule_id: string
  action: RuleAction
  protocol: RuleProtocol
  src_ip: string
  dst_ip: string | null
  dst_port: number | null
  description: string
  created_at: string
  created_by: string   // analysis_id or 'manual'
  active: boolean
}

export interface BlockRequest {
  ip: string
  reason: string
  analysis_id: string | null
  duration_hours: number | null  // null = permanent
}

export interface BlockResponse {
  success: boolean
  rule_id: string | null
  message: string
}
