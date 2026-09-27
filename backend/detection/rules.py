from typing import Any, Dict, List
from config import RULE_WEIGHTS


class DetectionRule:
    def __init__(self, rule_id: str, name: str, weight: int, severity: str, description: str):
        self.rule_id = rule_id
        self.name = name
        self.weight = weight
        self.severity = severity
        self.description = description

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError


class BrandImpersonationRule(DetectionRule):
    def __init__(self):
        cfg = RULE_WEIGHTS["brand_impersonation"]
        super().__init__("brand_impersonation", cfg["name"], cfg["weight"], cfg["severity"], cfg["description"])

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        triggered = bool(features.get("is_brand_impersonation", False))
        brand = features.get("detected_brand", "Unknown")
        loc = features.get("brand_impersonation_location", "domain")
        return {
            "rule_id": self.rule_id,
            "triggered": triggered,
            "name": self.name,
            "severity": self.severity,
            "score": self.weight if triggered else 0,
            "description": self.description,
            "detail": f"Impersonation of brand '{brand}' detected in unauthorized {loc}." if triggered else "No brand impersonation detected."
        }


class IPAddressRule(DetectionRule):
    def __init__(self):
        cfg = RULE_WEIGHTS["ip_address"]
        super().__init__("ip_address", cfg["name"], cfg["weight"], cfg["severity"], cfg["description"])

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        triggered = bool(features.get("has_ip_address", False))
        ip_type = "IPv4" if features.get("is_ipv4") else ("IPv6" if features.get("is_ipv6") else "Encoded/Decimal IP")
        return {
            "rule_id": self.rule_id,
            "triggered": triggered,
            "name": self.name,
            "severity": self.severity,
            "score": self.weight if triggered else 0,
            "description": self.description,
            "detail": f"Host is a raw {ip_type} address rather than a registered domain name." if triggered else "Standard domain name used as host."
        }


class AtSymbolRule(DetectionRule):
    def __init__(self):
        cfg = RULE_WEIGHTS["at_symbol"]
        super().__init__("at_symbol", cfg["name"], cfg["weight"], cfg["severity"], cfg["description"])

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        triggered = bool(features.get("has_at_symbol", False))
        return {
            "rule_id": self.rule_id,
            "triggered": triggered,
            "name": self.name,
            "severity": self.severity,
            "score": self.weight if triggered else 0,
            "description": self.description,
            "detail": "The '@' symbol is present. Browsers interpret characters before '@' as user credentials and route traffic to the trailing host." if triggered else "No '@' character in URL."
        }


class PunycodeRule(DetectionRule):
    def __init__(self):
        cfg = RULE_WEIGHTS["punycode_homoglyph"]
        super().__init__("punycode_homoglyph", cfg["name"], cfg["weight"], cfg["severity"], cfg["description"])

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        triggered = bool(features.get("has_punycode", False))
        return {
            "rule_id": self.rule_id,
            "triggered": triggered,
            "name": self.name,
            "severity": self.severity,
            "score": self.weight if triggered else 0,
            "description": self.description,
            "detail": "Punycode (xn--) detected. Visually similar Unicode characters can be used to forge lookalike domains of trusted organizations." if triggered else "Standard ASCII domain (no Punycode encoding)."
        }


class ExecutableDownloadRule(DetectionRule):
    def __init__(self):
        cfg = RULE_WEIGHTS["executable_download"]
        super().__init__("executable_download", cfg["name"], cfg["weight"], cfg["severity"], cfg["description"])

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        triggered = bool(features.get("has_executable_extension", False))
        ext = features.get("file_extension", "")
        return {
            "rule_id": self.rule_id,
            "triggered": triggered,
            "name": self.name,
            "severity": self.severity,
            "score": self.weight if triggered else 0,
            "description": self.description,
            "detail": f"Path points directly to an executable file ({ext}), a high-risk delivery pattern for malicious payloads." if triggered else "No executable extension detected."
        }


class OpenRedirectRule(DetectionRule):
    def __init__(self):
        cfg = RULE_WEIGHTS["open_redirect_param"]
        super().__init__("open_redirect_param", cfg["name"], cfg["weight"], cfg["severity"], cfg["description"])

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        triggered = bool(features.get("has_external_redirect_target", False))
        target = features.get("redirect_target_url", "")
        return {
            "rule_id": self.rule_id,
            "triggered": triggered,
            "name": self.name,
            "severity": self.severity,
            "score": self.weight if triggered else 0,
            "description": self.description,
            "detail": f"Query specifies an external target destination: {target}" if triggered else "No external redirect parameters detected."
        }


class URLShortenerRule(DetectionRule):
    def __init__(self):
        cfg = RULE_WEIGHTS["url_shortener"]
        super().__init__("url_shortener", cfg["name"], cfg["weight"], cfg["severity"], cfg["description"])

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        triggered = bool(features.get("has_url_shortener", False))
        return {
            "rule_id": self.rule_id,
            "triggered": triggered,
            "name": self.name,
            "severity": self.severity,
            "score": self.weight if triggered else 0,
            "description": self.description,
            "detail": "URL routes through a public shortener, obscuring the authentic landing destination." if triggered else "Direct domain (no URL shortener)."
        }


class ExcessiveSubdomainsRule(DetectionRule):
    def __init__(self):
        cfg = RULE_WEIGHTS["excessive_subdomains"]
        super().__init__("excessive_subdomains", cfg["name"], cfg["weight"], cfg["severity"], cfg["description"])

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        sub_count = features.get("subdomain_count", 0)
        triggered = sub_count >= 3
        return {
            "rule_id": self.rule_id,
            "triggered": triggered,
            "name": self.name,
            "severity": self.severity,
            "score": self.weight if triggered else 0,
            "description": self.description,
            "detail": f"{sub_count} subdomain levels detected, often engineered to spoof complex enterprise hierarchies." if triggered else f"{sub_count} subdomain levels (within standard bounds)."
        }


class SuspiciousTLDRule(DetectionRule):
    def __init__(self):
        cfg = RULE_WEIGHTS["suspicious_tld"]
        super().__init__("suspicious_tld", cfg["name"], cfg["weight"], cfg["severity"], cfg["description"])

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        triggered = bool(features.get("has_suspicious_tld", False))
        tld_val = features.get("domain_analysis", {}).get("tld", "")
        return {
            "rule_id": self.rule_id,
            "triggered": triggered,
            "name": self.name,
            "severity": self.severity,
            "score": self.weight if triggered else 0,
            "description": self.description,
            "detail": f"Domain utilizes high-risk TLD '{tld_val}', statistically overrepresented in disposable phishing campaigns." if triggered else f"TLD '{tld_val}' is a standard or low-abuse top-level domain."
        }


class DomainEntropyRule(DetectionRule):
    def __init__(self):
        cfg = RULE_WEIGHTS["domain_entropy_anomaly"]
        super().__init__("domain_entropy_anomaly", cfg["name"], cfg["weight"], cfg["severity"], cfg["description"])

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        triggered = bool(features.get("has_high_domain_entropy", False))
        dom_entropy = features.get("domain_entropy", 0.0)
        host_entropy = features.get("hostname_entropy", 0.0)
        return {
            "rule_id": self.rule_id,
            "triggered": triggered,
            "name": self.name,
            "severity": self.severity,
            "score": self.weight if triggered else 0,
            "description": self.description,
            "detail": f"Unusually high character entropy (domain: {dom_entropy}, host: {host_entropy}), typical of algorithmically generated domains (DGA)." if triggered else f"Character entropy is normal ({dom_entropy})."
        }


class HyphenHeavyDomainRule(DetectionRule):
    def __init__(self):
        cfg = RULE_WEIGHTS["hyphen_heavy_domain"]
        super().__init__("hyphen_heavy_domain", cfg["name"], cfg["weight"], cfg["severity"], cfg["description"])

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        hyphen_count = features.get("domain_hyphen_count", 0)
        triggered = bool(features.get("is_hyphen_heavy_domain", False))
        return {
            "rule_id": self.rule_id,
            "triggered": triggered,
            "name": self.name,
            "severity": self.severity,
            "score": self.weight if triggered else 0,
            "description": self.description,
            "detail": f"Domain name contains {hyphen_count} hyphens, a pattern commonly used to string brand names with lures (e.g. 'paypal-account-center')." if triggered else f"Domain contains {hyphen_count} hyphens (normal)."
        }


class SuspiciousPortRule(DetectionRule):
    def __init__(self):
        cfg = RULE_WEIGHTS["suspicious_port"]
        super().__init__("suspicious_port", cfg["name"], cfg["weight"], cfg["severity"], cfg["description"])

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        triggered = bool(features.get("has_suspicious_port", False))
        port = features.get("custom_port")
        return {
            "rule_id": self.rule_id,
            "triggered": triggered,
            "name": self.name,
            "severity": self.severity,
            "score": self.weight if triggered else 0,
            "description": self.description,
            "detail": f"Non-standard web port {port} specified, bypassing standard firewall web filtering." if triggered else "Standard web port in use (80 or 443)."
        }


class ContextualKeywordsRule(DetectionRule):
    def __init__(self):
        cfg = RULE_WEIGHTS["contextual_keywords"]
        super().__init__("contextual_keywords", cfg["name"], cfg["weight"], cfg["severity"], cfg["description"])

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        # Contextual intelligence: Do NOT penalize verified domains like github.com/login!
        is_contextually_suspicious = bool(features.get("is_contextually_suspicious", False))
        kw_in_host = features.get("keywords_in_host", [])
        kw_in_path = features.get("keywords_in_path", [])
        threat_level = features.get("keyword_threat_level", "NONE")

        triggered = is_contextually_suspicious
        score = 0

        if triggered:
            if threat_level == "HOST_DECEPTION" or len(kw_in_host) > 0:
                # Highly deceptive: keyword in host name (e.g. login-verify-bank.com)
                score = self.weight
            elif threat_level == "MULTIPLE_CREDENTIAL_LURES":
                score = min(20, self.weight)
            else:
                # Moderate: keyword in path on an unknown domain
                score = 8

        detail_text = (
            f"Contextually suspicious keyword lures: Host [{', '.join(kw_in_host)}], Path [{', '.join(kw_in_path)}]."
            if triggered else "Keywords are within standard benign context or absent."
        )

        return {
            "rule_id": self.rule_id,
            "triggered": triggered,
            "name": self.name,
            "severity": self.severity,
            "score": score,
            "description": self.description,
            "detail": detail_text
        }


class DoubleSlashPathRule(DetectionRule):
    def __init__(self):
        cfg = RULE_WEIGHTS["double_slash_path"]
        super().__init__("double_slash_path", cfg["name"], cfg["weight"], cfg["severity"], cfg["description"])

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        triggered = bool(features.get("has_double_slash_path", False))
        return {
            "rule_id": self.rule_id,
            "triggered": triggered,
            "name": self.name,
            "severity": self.severity,
            "score": self.weight if triggered else 0,
            "description": self.description,
            "detail": "Path contains consecutive slashes ('//'), an indicator of open redirection evasion tricks." if triggered else "Clean URL path formatting."
        }


class HttpUnencryptedRule(DetectionRule):
    def __init__(self):
        cfg = RULE_WEIGHTS["http_unencrypted"]
        super().__init__("http_unencrypted", cfg["name"], cfg["weight"], cfg["severity"], cfg["description"])

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        triggered = bool(features.get("has_http", False))
        return {
            "rule_id": self.rule_id,
            "triggered": triggered,
            "name": self.name,
            "severity": self.severity,
            "score": self.weight if triggered else 0,
            "description": self.description,
            "detail": "URL uses unencrypted HTTP protocol without TLS. Credentials and tokens can be intercepted in transit." if triggered else "HTTPS encrypted protocol in use."
        }


class ExcessiveURLLengthRule(DetectionRule):
    def __init__(self):
        cfg = RULE_WEIGHTS["excessive_url_length"]
        super().__init__("excessive_url_length", cfg["name"], cfg["weight"], cfg["severity"], cfg["description"])

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        url_len = features.get("url_length", 0)
        triggered = url_len > 80
        score = self.weight if triggered else 0
        if url_len > 130:
            score = 15
        return {
            "rule_id": self.rule_id,
            "triggered": triggered,
            "name": self.name,
            "severity": self.severity,
            "score": score,
            "description": self.description,
            "detail": f"URL length is {url_len} characters. Abnormally long URLs are often crafted to obscure true destinations." if triggered else f"URL length is {url_len} characters (within standard bounds)."
        }


class PercentEncodedRule(DetectionRule):
    def __init__(self):
        cfg = RULE_WEIGHTS["percent_encoded"]
        super().__init__("percent_encoded", cfg["name"], cfg["weight"], cfg["severity"], cfg["description"])

    def evaluate(self, features: Dict[str, Any]) -> Dict[str, Any]:
        count = features.get("percent_encoding_count", 0)
        triggered = count >= 2
        return {
            "rule_id": self.rule_id,
            "triggered": triggered,
            "name": self.name,
            "severity": self.severity,
            "score": self.weight if triggered else 0,
            "description": self.description,
            "detail": f"Contains {count} percent-encoded hexadecimal sequences used to obscure payload tokens." if triggered else "No percent encoding obfuscation detected."
        }


def get_all_rules() -> List[DetectionRule]:
    return [
        BrandImpersonationRule(),
        IPAddressRule(),
        AtSymbolRule(),
        PunycodeRule(),
        ExecutableDownloadRule(),
        OpenRedirectRule(),
        URLShortenerRule(),
        ExcessiveSubdomainsRule(),
        SuspiciousTLDRule(),
        DomainEntropyRule(),
        HyphenHeavyDomainRule(),
        SuspiciousPortRule(),
        ContextualKeywordsRule(),
        DoubleSlashPathRule(),
        HttpUnencryptedRule(),
        ExcessiveURLLengthRule(),
        PercentEncodedRule(),
    ]
