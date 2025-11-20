export enum Severity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
  SAFE = 'SAFE'
}

export enum AnalysisType {
  SQL_INJECTION = 'SQL_INJECTION',
  PHISHING = 'PHISHING',
  MALWARE = 'MALWARE',
  PACKET_INSPECTION = 'PACKET_INSPECTION',
  DOS_DDOS = 'DOS_DDOS'
}

export interface ThreatLog {
  id: string;
  timestamp: string;
  type: AnalysisType;
  severity: Severity;
  source: string;
  details: string;
  blocked: boolean;
}

export interface Packet {
  id: string;
  timestamp: number;
  sourceIp: string;
  destIp: string;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'HTTP';
  port: number;
  payload: string;
  status: 'ALLOWED' | 'BLOCKED_L4' | 'BLOCKED_L7' | 'BLOCKED_AI' | 'ANALYZING';
  riskScore?: number;
  verdictReason?: string;
}

export interface AnalysisResult {
  isThreat: boolean;
  severity: Severity;
  reasoning: string;
  suggestedAction: string;
  technicalDetails?: string;
}

export enum TabView {
  DASHBOARD = 'DASHBOARD',
  SQL_DETECTOR = 'SQL_DETECTOR',
  PHISHING_MALWARE = 'PHISHING_MALWARE',
  NETWORK_GUARD = 'NETWORK_GUARD',
  DOS_GUARD = 'DOS_GUARD',
  DOCUMENTATION = 'DOCUMENTATION'
}

export interface FirewallRule {
  id: string;
  type: 'L4_PORT' | 'L4_IP' | 'L7_KEYWORD';
  value: string | number;
  active: boolean;
}