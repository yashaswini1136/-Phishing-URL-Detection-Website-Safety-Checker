export type ClassificationType = 'SAFE' | 'SUSPICIOUS' | 'PHISHING' | 'POTENTIAL_PHISHING';
export type RiskLevelType = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type SeverityType = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface Indicator {
  rule_id: string;
  triggered: boolean;
  name: string;
  severity: SeverityType;
  score: number;
  description: string;
  detail: string;
}

export interface DomainAnalysis {
  protocol: string;
  hostname: string;
  registered_domain: string;
  subdomain: string;
  tld: string;
  port: number;
  is_custom_port: boolean;
  path: string;
  query_parameters: string[];
  is_ip_based: boolean;
  is_shortener: boolean;
  is_punycode: boolean;
  analysis_type: string;
}

export interface URLFeatures {
  url_length: number;
  domain_length: number;
  path_length: number;
  query_length: number;
  dot_count: number;
  hyphen_count: number;
  underscore_count: number;
  slash_count: number;
  digit_count: number;
  special_character_count: number;
  subdomain_count: number;
  query_param_count: number;
  path_depth: number;

  has_https: boolean;
  has_http: boolean;
  has_ip_address: boolean;
  has_url_shortener: boolean;
  has_at_symbol: boolean;
  has_double_slash_path: boolean;
  has_punycode: boolean;
  has_percent_encoding: boolean;
  percent_encoding_count: number;
  has_suspicious_tld: boolean;
  has_suspicious_port: boolean;
  custom_port: number | null;
  has_long_hostname: boolean;
  domain_hyphen_count: number;
  is_hyphen_heavy_domain: boolean;

  suspicious_keyword_count: number;
  found_keywords: string[];
  has_login_keywords: boolean;
  has_account_keywords: boolean;
  has_payment_keywords: boolean;
  has_urgency_keywords: boolean;
  domain_analysis: DomainAnalysis;

  // Multi-dimensional threat & entropy attributes
  entropy_hostname?: number;
  entropy_domain?: number;
  entropy_path?: number;
  has_brand_impersonation?: boolean;
  impersonated_brand?: string | null;
  is_authorized_brand?: boolean;
  has_redirect_param?: boolean;
  has_executable_ext?: boolean;
  has_hex_ip?: boolean;
  has_octal_ip?: boolean;
  has_dword_ip?: boolean;
  has_ipv6?: boolean;
}

export interface MLMetadata {
  detection_method: string;
  ml_available: boolean;
  ml_phishing_probability: number | null;
  ml_prediction: string | null;
  hybrid_confidence: string | null;
  model_type?: string;
  features_used?: number;
}

export interface AnalysisResult {
  id: number;
  url: string;
  original_url: string;
  normalized_url?: string;
  classification: ClassificationType;
  risk_score: number;
  confidence: number;
  risk_level: RiskLevelType;
  indicator_count: number;
  indicators: Indicator[];
  legitimacy_credits?: number;
  recommendations: string[];
  features: URLFeatures;
  domain_analysis: DomainAnalysis;
  detection_method: string;
  ml_metadata?: MLMetadata;
  processing_time_ms?: number;
  timestamp: string;
  disclaimer: string;
}

export interface ScanHistoryItem {
  id: number;
  url: string;
  timestamp: string;
  risk_score: number;
  confidence?: number;
  risk_level: RiskLevelType;
  classification: ClassificationType;
  indicator_count: number;
  detection_method: string;
}

export interface Statistics {
  total_scans: number;
  safe_count: number;
  suspicious_count: number;
  phishing_count: number;
  detection_rate: number;
  avg_risk_score: number;
  top_indicators: { name: string; count: number }[];
}

export interface DetectionRule {
  rule_id: string;
  name: string;
  weight: number;
  severity: SeverityType;
  description: string;
}
