import json
import os
from pathlib import Path
from typing import Any, Dict, List, Set

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "database" / "phishing_detector.db"))
MODEL_PATH = os.getenv("MODEL_PATH", str(BASE_DIR / "models" / "phishing_model.joblib"))
SCALER_PATH = os.getenv("SCALER_PATH", str(BASE_DIR / "models" / "scaler.joblib"))
DATASET_PATH = os.getenv("DATASET_PATH", str(BASE_DIR / "dataset" / "urls.csv"))
BRANDS_PATH = os.getenv("BRANDS_PATH", str(BASE_DIR / "brands.json"))

# Calibrated Risk Score Thresholds
# 0 - 29: LOW RISK (SAFE)
# 30 - 59: MEDIUM RISK (SUSPICIOUS)
# 60 - 100: HIGH / CRITICAL RISK (POTENTIAL_PHISHING)
SAFE_THRESHOLD = 29
SUSPICIOUS_THRESHOLD = 59
PHISHING_THRESHOLD = 60

RISK_THRESHOLDS = {
    "safe_max": SAFE_THRESHOLD,
    "suspicious_max": SUSPICIOUS_THRESHOLD,
    "phishing_min": PHISHING_THRESHOLD,
}

# Hybrid Score Fusion Weights (Rule Engine + Machine Learning Model)
# Calibrated so deterministic indicators maintain strong signal while ML provides pattern density
RULE_WEIGHT = float(os.getenv("RULE_WEIGHT", "0.55"))
ML_WEIGHT = float(os.getenv("ML_WEIGHT", "0.45"))

# Configurable Rule Weights and Threat Metadata
RULE_WEIGHTS: Dict[str, Dict[str, Any]] = {
    "brand_impersonation": {
        "name": "Brand Impersonation Vector",
        "weight": 25,
        "severity": "HIGH",
        "description": "The URL incorporates a recognized brand name in an unauthorized domain, subdomain, or misleading prefix (e.g. 'paypal-security-update.xyz')."
    },
    "ip_address": {
        "name": "IP Address Used as Hostname",
        "weight": 25,
        "severity": "HIGH",
        "description": "The hostname is a raw IP address (IPv4, IPv6, or encoded decimal/hex) rather than a registered domain name. Legitimate web services generally avoid raw IP hosts."
    },
    "at_symbol": {
        "name": "@ Symbol Obfuscation",
        "weight": 25,
        "severity": "HIGH",
        "description": "The '@' character causes browsers to treat preceding characters as authentication credentials and connect directly to the trailing host."
    },
    "punycode_homoglyph": {
        "name": "Punycode / IDN Homoglyph Spoofing",
        "weight": 20,
        "severity": "HIGH",
        "description": "Domain contains Punycode ('xn--') encoding, frequently leveraged to visually impersonate popular brand names using lookalike Cyrillic or non-Latin alphabets."
    },
    "executable_download": {
        "name": "Suspicious Executable File Extension",
        "weight": 25,
        "severity": "HIGH",
        "description": "The URL path targets a direct executable or script payload (e.g., .exe, .scr, .bat, .apk, .vbs), typical of malicious download delivery campaigns."
    },
    "open_redirect_param": {
        "name": "External Open Redirect Parameter",
        "weight": 15,
        "severity": "MEDIUM",
        "description": "URL query parameters specify an external target destination (e.g., ?redirect=https://evil.com), often exploited to redirect users from trusted hosts to phishing landing pages."
    },
    "url_shortener": {
        "name": "URL Shortener Service Detected",
        "weight": 15,
        "severity": "MEDIUM",
        "description": "The domain routes through a public URL shortening service, masking the authentic destination and preventing static domain verification."
    },
    "excessive_subdomains": {
        "name": "Excessive Subdomain Stacking",
        "weight": 15,
        "severity": "MEDIUM",
        "description": "Hostname exhibits 3 or more subdomain levels, a pattern commonly engineered to simulate authentic enterprise hierarchy (e.g. login.secure.bank.com.fake.site)."
    },
    "suspicious_tld": {
        "name": "High-Risk Top-Level Domain (TLD)",
        "weight": 12,
        "severity": "MEDIUM",
        "description": "The domain is registered under a high-abuse TLD statistically overrepresented in disposable phishing campaigns (.xyz, .top, .click, .buzz, etc.)."
    },
    "domain_entropy_anomaly": {
        "name": "High Randomness / Domain Entropy",
        "weight": 12,
        "severity": "MEDIUM",
        "description": "Hostname or registered domain exhibits unusually high Shannon entropy, indicating algorithmically generated domains (DGA) or machine-generated obfuscation."
    },
    "hyphen_heavy_domain": {
        "name": "Hyphen-Stuffed Domain Structure",
        "weight": 12,
        "severity": "MEDIUM",
        "description": "Domain name contains multiple hyphens, typically used to combine legitimate brand names with security terms (e.g. 'microsoft-login-verify')."
    },
    "suspicious_port": {
        "name": "Non-Standard Web Port",
        "weight": 15,
        "severity": "MEDIUM",
        "description": "URL targets a non-standard port (e.g. 8080, 8888, 2082), bypassing standard web traffic inspection rules for ports 80 and 443."
    },
    "contextual_keywords": {
        "name": "Contextual Phishing Keyword Lures",
        "weight": 15,
        "severity": "MEDIUM",
        "description": "Contains sensitive authentication, account security, or urgency keywords within an unauthorized or suspicious domain structure."
    },
    "double_slash_path": {
        "name": "Double Slash in URL Path",
        "weight": 12,
        "severity": "MEDIUM",
        "description": "Path segment contains consecutive slashes ('//'), frequently used in evasion vectors to bypass URL filtering gateways."
    },
    "http_unencrypted": {
        "name": "Unencrypted HTTP Connection",
        "weight": 10,
        "severity": "LOW",
        "description": "The URL uses plain unencrypted HTTP. Plaintext transmission allows credential interception via Man-in-the-Middle (MitM) attacks."
    },
    "excessive_url_length": {
        "name": "Abnormally Long URL String",
        "weight": 10,
        "severity": "LOW",
        "description": "URL length exceeds 80 characters, often crafted to push hostile domain tokens offscreen in mobile viewports or embed obfuscated payloads."
    },
    "percent_encoded": {
        "name": "Hexadecimal Percent Obfuscation",
        "weight": 10,
        "severity": "LOW",
        "description": "Excessive percent-encoding (%xx) in the hostname or path used to obscure characters from simple pattern scanners."
    }
}

# Positive Legitimacy Evidence Credits (Negative Weights)
LEGITIMACY_CREDITS = {
    "verified_brand_domain": {
        "credit": -20,
        "reason": "Hostname and registered domain match an authorized, verified brand domain (e.g. github.com, google.com). This provides strong positive evidence against phishing."
    },
    "clean_registered_structure": {
        "credit": -5,
        "reason": "Domain displays standard apex structure, normal character entropy, standard ports, and absence of obfuscation techniques."
    }
}

# Known Public URL Shorteners
SHORTENER_DOMAINS: Set[str] = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "tiny.cc", "shorte.st",
    "rb.gy", "bl.ink", "lnkd.in", "s.id", "soo.gd", "snip.ly", "v.gd", "qr.ae"
}

# High-Risk / Suspicious TLDs
SUSPICIOUS_TLDS: Set[str] = {
    "xyz", "top", "work", "click", "loan", "fit", "country", "gq", "tk", "ml",
    "ga", "cf", "buzz", "rest", "icu", "surf", "casa", "kim", "monster", "cfd",
    "quest", "sbs", "support", "uno", "live", "vip", "beauty", "hair", "skin",
    "pw", "cc", "ws"
}

# Suspicious keywords categorized by threat context
SUSPICIOUS_KEYWORDS: Dict[str, List[str]] = {
    "authentication": [
        "login", "signin", "sign-in", "log-in", "auth", "authenticate", "portal",
        "password", "credential", "session", "passcode", "access", "oauth"
    ],
    "account": [
        "account", "verify", "verification", "secure", "security", "update",
        "confirm", "confirmation", "validate", "validation", "recover", "recovery",
        "locked", "suspended", "restore", "unlock", "alert", "notice", "kyc"
    ],
    "financial": [
        "bank", "banking", "wallet", "payment", "pay", "invoice", "paypal",
        "billing", "card", "debit", "credit", "checkout", "crypto", "bitcoin",
        "webscr", "transaction", "transfer", "fund", "wire"
    ],
    "urgency": [
        "urgent", "immediately", "immediate", "suspended", "locked", "expired",
        "warning", "reward", "winner", "claim", "free", "bonus", "prize", "limited"
    ]
}

ALL_SUSPICIOUS_KEYWORDS: Set[str] = {
    kw for cat in SUSPICIOUS_KEYWORDS.values() for kw in cat
}

# Redirect-like query parameter keys
REDIRECT_PARAM_NAMES: Set[str] = {
    "url", "redirect", "redirect_url", "redirect_uri", "next", "return",
    "return_url", "continue", "target", "dest", "destination", "r", "u",
    "link", "goto", "out"
}

# Dangerous / Executable extensions
EXECUTABLE_EXTENSIONS: Set[str] = {
    ".exe", ".scr", ".bat", ".cmd", ".apk", ".vbs", ".sh", ".msi",
    ".jar", ".ps1", ".hta", ".pif", ".cpl", ".wsf", ".iso"
}

# Standard web ports
STANDARD_PORTS: Set[int] = {80, 443}

# Known Top Legitimate Organizations and Verified Domains
# Used for positive legitimacy evidence and suppressing false positives on standard /login paths
VERIFIED_LEGITIMATE_DOMAINS: Set[str] = {
    "google.com", "accounts.google.com", "mail.google.com", "drive.google.com",
    "microsoft.com", "login.microsoftonline.com", "account.microsoft.com",
    "apple.com", "appleid.apple.com", "icloud.com",
    "github.com", "github.io",
    "amazon.com", "aws.amazon.com",
    "paypal.com",
    "wikipedia.org", "wikimedia.org",
    "netflix.com",
    "linkedin.com",
    "stackoverflow.com", "stackexchange.com",
    "cloudflare.com",
    "python.org",
    "mozilla.org",
    "reddit.com",
    "twitter.com", "x.com",
    "facebook.com", "instagram.com", "whatsapp.com",
    "spotify.com",
    "dropbox.com",
    "zoom.us",
    "adobe.com",
    "slack.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "harvard.edu", "mit.edu", "stanford.edu",
    "cnn.com", "bbc.com", "nytimes.com",
    "ebay.com", "stripe.com", "gitlab.com"
}


def load_brands_database() -> Dict[str, List[str]]:
    """Loads brand names and their authorized registered domains from brands.json."""
    if os.path.exists(BRANDS_PATH):
        try:
            with open(BRANDS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[Config] Error loading brands.json: {e}")
    return {}


BRANDS_DATABASE = load_brands_database()
