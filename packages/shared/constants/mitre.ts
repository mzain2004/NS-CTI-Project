import type { RiskLevel } from '../types'

// ── MITRE ATT&CK Tactic Names (TA00xx) ─────────────────────────────────────
export const MITRE_TACTICS = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
] as const

export type MitreTactic = (typeof MITRE_TACTICS)[number]

// ── MITRE Tactic → TA ID mapping ───────────────────────────────────────────
export const TACTIC_TO_ID: Record<MitreTactic, string> = {
  Reconnaissance: 'TA0043',
  'Resource Development': 'TA0042',
  'Initial Access': 'TA0001',
  Execution: 'TA0002',
  Persistence: 'TA0003',
  'Privilege Escalation': 'TA0004',
  'Defense Evasion': 'TA0005',
  'Credential Access': 'TA0006',
  Discovery: 'TA0007',
  'Lateral Movement': 'TA0008',
  Collection: 'TA0009',
  'Command and Control': 'TA0011',
  Exfiltration: 'TA0010',
  Impact: 'TA0040',
}

// ── Risk Level UI colors (Tailwind / CSS var compatible) ──────────────────
export const RISK_LEVEL_COLORS: Record<RiskLevel, string> = {
  LOW: '#22c55e',      // green-500
  MEDIUM: '#f5a623',   // amber
  HIGH: '#f97316',     // orange-500
  CRITICAL: '#ff4d4f', // danger red
}

export const RISK_LEVEL_BG: Record<RiskLevel, string> = {
  LOW: 'rgba(34,197,94,0.15)',
  MEDIUM: 'rgba(245,166,35,0.15)',
  HIGH: 'rgba(249,115,22,0.15)',
  CRITICAL: 'rgba(255,77,79,0.15)',
}

// ── Wazuh rule level → risk level mapping ──────────────────────────────────
export function wazuhLevelToRisk(level: number): RiskLevel {
  if (level >= 13) return 'CRITICAL'
  if (level >= 10) return 'HIGH'
  if (level >= 7) return 'MEDIUM'
  return 'LOW'
}
