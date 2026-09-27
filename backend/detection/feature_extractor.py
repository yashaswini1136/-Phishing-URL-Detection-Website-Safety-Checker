import ipaddress
import math
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, unquote, urlparse

import tldextract

from config import (
    ALL_SUSPICIOUS_KEYWORDS,
    BASE_DIR,
    BRANDS_DATABASE,
    EXECUTABLE_EXTENSIONS,
    REDIRECT_PARAM_NAMES,
    SHORTENER_DOMAINS,
    STANDARD_PORTS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    VERIFIED_LEGITIMATE_DOMAINS,
)

# Initialize local offline tldextract instance (suffix_list_urls=None ensures ZERO external network calls)
tld_cache_dir = str(BASE_DIR / "database" / ".tld_cache")
os.makedirs(tld_cache_dir, exist_ok=True)
_extractor = tldextract.TLDExtract(cache_dir=tld_cache_dir, suffix_list_urls=None)


def calculate_entropy(text: str) -> float:
    """
    Computes Shannon entropy of a string.
    Higher entropy indicates random/algorithmically generated strings or high variance.
    """
    if not text:
        return 0.0
    text_len = len(text)
    frequencies = [text.count(c) / text_len for c in set(text)]
    return round(-sum(p * math.log2(p) for p in frequencies), 3)


def normalize_url(raw_url: str) -> Tuple[str, str, bool, Optional[str]]:
    """
    Layer 1: Normalization Pipeline
    Preserves original_url while producing a normalized, sanitized version.
    Returns: (original_url, normalized_url, is_valid, error_message)
    Safe pattern-only check without any network lookups.
    """
    if not raw_url or not isinstance(raw_url, str):
        return "", "", False, "URL cannot be empty"

    original_url = raw_url.strip()

    # Reject whitespace within the URL or excessive length
    if " " in original_url:
        return original_url, "", False, "URL cannot contain spaces"

    if len(original_url) > 2048:
        return original_url, "", False, "URL exceeds maximum allowed length of 2048 characters"

    # Add default scheme if missing for parsing purposes
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", original_url))
    url_to_parse = original_url if has_scheme else "http://" + original_url

    try:
        parsed = urlparse(url_to_parse)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc

        if not netloc and not parsed.path:
            return original_url, "", False, "Invalid URL structure: missing domain or host"

        hostname = parsed.hostname
        if not hostname:
            return original_url, "", False, "Invalid URL structure: cannot determine hostname"

        # Sanity check for illegal injection characters in hostname
        if any(c in hostname for c in ["<", ">", '"', "'", "`", "{", "}", "|", "\\", "^"]):
            return original_url, "", False, "URL contains illegal characters in hostname"

        # Reconstruct normalized URL: lowercase scheme & host, preserve userinfo, path & query
        normalized_host = hostname.lower()
        if parsed.port:
            normalized_host = f"{normalized_host}:{parsed.port}"

        userinfo_prefix = ""
        if "@" in netloc:
            userinfo_prefix = netloc.split("@")[0] + "@"

        # Preserve path, query, fragment
        path = parsed.path or "/"
        query_str = f"?{parsed.query}" if parsed.query else ""
        frag_str = f"#{parsed.fragment}" if parsed.fragment else ""

        normalized_url = f"{scheme}://{userinfo_prefix}{normalized_host}{path}{query_str}{frag_str}"
        return original_url, normalized_url, True, None
    except Exception as e:
        return original_url, "", False, f"URL normalization error: {str(e)}"


def parse_domain_components(hostname: str) -> Dict[str, Any]:
    """
    Layer 3: Domain Analysis via tldextract
    Determines scheme, subdomain, registered domain, and suffix/TLD.
    """
    if not hostname:
        return {
            "registered_domain": "",
            "domain": "",
            "subdomain": "",
            "subdomain_count": 0,
            "subdomain_length": 0,
            "tld": "",
            "is_ip": False,
        }

    is_ip = detect_ip_address(hostname)["has_ip"]
    if is_ip:
        return {
            "registered_domain": hostname,
            "domain": hostname,
            "subdomain": "",
            "subdomain_count": 0,
            "subdomain_length": 0,
            "tld": "",
            "is_ip": True,
        }

    try:
        extracted = _extractor(hostname)
        subdomain = extracted.subdomain
        domain = extracted.domain
        suffix = extracted.suffix

        subdomain_parts = [p for p in subdomain.split(".") if p] if subdomain else []
        subdomain_count = len(subdomain_parts)
        registered_domain = f"{domain}.{suffix}" if (domain and suffix) else (domain or hostname)

        return {
            "registered_domain": registered_domain.lower(),
            "domain": domain.lower() if domain else "",
            "subdomain": subdomain.lower(),
            "subdomain_count": subdomain_count,
            "subdomain_length": len(subdomain),
            "tld": suffix.lower(),
            "is_ip": False,
        }
    except Exception:
        # Fallback to simple split if extraction fails
        parts = hostname.lower().split(".")
        return {
            "registered_domain": hostname,
            "domain": parts[0] if parts else "",
            "subdomain": ".".join(parts[:-2]) if len(parts) > 2 else "",
            "subdomain_count": max(0, len(parts) - 2),
            "subdomain_length": len(".".join(parts[:-2])) if len(parts) > 2 else 0,
            "tld": parts[-1] if len(parts) > 1 else "",
            "is_ip": False,
        }


def detect_ip_address(hostname: str) -> Dict[str, Any]:
    """
    Layer 4: IP Address Detection
    Detects IPv4, IPv6, Hexadecimal IP, and Decimal Integer IP.
    """
    if not hostname:
        return {"has_ip": False, "is_ipv4": False, "is_ipv6": False, "is_decimal_ip": False, "is_hex_ip": False}

    clean = hostname.strip()
    if clean.startswith("[") and "]" in clean:
        clean_host = clean[1:clean.index("]")]
    elif ":" in clean and clean.count(":") == 1:
        clean_host = clean.split(":")[0]
    else:
        clean_host = clean

    # Standard IP address parsing
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        is_v4 = isinstance(ip_obj, ipaddress.IPv4Address)
        is_v6 = isinstance(ip_obj, ipaddress.IPv6Address)
        return {
            "has_ip": True,
            "is_ipv4": is_v4,
            "is_ipv6": is_v6,
            "is_decimal_ip": False,
            "is_hex_ip": False,
        }
    except ValueError:
        pass

    # Regex check for standard IPv4 notation
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if re.match(ipv4_pattern, clean_host):
        return {"has_ip": True, "is_ipv4": True, "is_ipv6": False, "is_decimal_ip": False, "is_hex_ip": False}

    # Hexadecimal IP pattern (e.g. 0x7f.0x0.0x0.0x1 or 0x7f000001)
    if re.match(r"^0x[0-9a-fA-F]+(?:\.0x[0-9a-fA-F]+){3}$", clean_host) or re.match(r"^0x[0-9a-fA-F]{8}$", clean_host):
        return {"has_ip": True, "is_ipv4": False, "is_ipv6": False, "is_decimal_ip": False, "is_hex_ip": True}

    # Decimal integer IP pattern (e.g. http://2130706433)
    if clean_host.isdigit() and len(clean_host) >= 8:
        try:
            val = int(clean_host)
            if 0 < val <= 4294967295:
                return {"has_ip": True, "is_ipv4": False, "is_ipv6": False, "is_decimal_ip": True, "is_hex_ip": False}
        except ValueError:
            pass

    return {"has_ip": False, "is_ipv4": False, "is_ipv6": False, "is_decimal_ip": False, "is_hex_ip": False}


def detect_brand_impersonation(
    hostname: str,
    domain_info: Dict[str, Any],
    path: str,
    userinfo: str = ""
) -> Dict[str, Any]:
    """
    Layer 5: Brand Impersonation Detection
    Compares domain/subdomain tokens against brands.json database.
    Distinguishes authentic brand domains from deceptive spoofing attempts.
    """
    registered_domain = domain_info.get("registered_domain", "").lower()
    subdomain = domain_info.get("subdomain", "").lower()
    hostname_lower = hostname.lower()
    path_lower = path.lower()
    userinfo_lower = userinfo.lower()

    detected_brand = None
    is_impersonation = False
    is_authorized = False
    impersonation_location = None
    matched_authorized_domains: List[str] = []

    for brand, auth_domains in BRANDS_DATABASE.items():
        brand_lower = brand.lower()

        # Check if the brand name is present in the registered domain, subdomain, userinfo, or path
        in_reg_domain = brand_lower in registered_domain
        in_subdomain = brand_lower in subdomain
        in_userinfo = brand_lower in userinfo_lower
        in_path = (f"/{brand_lower}" in path_lower) or (f"-{brand_lower}" in path_lower)

        if in_reg_domain or in_subdomain or in_userinfo or in_path:
            detected_brand = brand
            matched_authorized_domains = auth_domains

            # Check if this URL is legitimately authorized under this brand
            is_domain_authorized = any(
                registered_domain == auth_dom or registered_domain.endswith("." + auth_dom)
                for auth_dom in auth_domains
            )

            if is_domain_authorized:
                # Legitimate brand site (e.g., github.com, accounts.google.com, apple.com)
                is_authorized = True
                is_impersonation = False
                break
            else:
                # Unofficial domain using brand name!
                if in_userinfo:
                    is_impersonation = True
                    impersonation_location = "authority_credential_prefix"
                    break
                elif in_reg_domain:
                    # Brand in registered domain (e.g., paypal-security.xyz or fake-microsoft.com)
                    is_impersonation = True
                    impersonation_location = "registered_domain"
                    break
                elif in_subdomain:
                    # Brand in subdomain (e.g., paypal.com.attacker-site.com)
                    is_impersonation = True
                    impersonation_location = "subdomain"
                    break
                elif in_path and ("login" in path_lower or "verify" in path_lower or "secure" in path_lower):
                    # Brand in path alongside credential harvesting lure
                    is_impersonation = True
                    impersonation_location = "path"
                    break

    return {
        "detected_brand": detected_brand,
        "is_brand_impersonation": is_impersonation,
        "is_brand_authorized": is_authorized,
        "impersonation_location": impersonation_location,
        "authorized_domains": matched_authorized_domains,
    }


def analyze_redirect_parameters(query: str) -> Dict[str, Any]:
    """
    Layer 4: Redirect Parameter Analysis
    Checks for ?redirect=, ?next=, ?url= pointing to external websites.
    """
    if not query:
        return {"has_redirect_param": False, "redirect_params": [], "has_external_target": False, "target_url": None}

    parsed_q = parse_qs(query)
    found_redirects = []
    has_external = False
    target_url = None

    for param_name, values in parsed_q.items():
        if param_name.lower() in REDIRECT_PARAM_NAMES:
            found_redirects.append(param_name)
            for val in values:
                decoded = unquote(val).strip()
                if decoded.startswith("http://") or decoded.startswith("https://") or decoded.startswith("//"):
                    has_external = True
                    target_url = decoded
                    break

    return {
        "has_redirect_param": len(found_redirects) > 0,
        "redirect_params": found_redirects,
        "has_external_target": has_external,
        "target_url": target_url,
    }


def detect_suspicious_keywords_context(
    url: str,
    hostname: str,
    domain_info: Dict[str, Any],
    path: str,
    query: str,
    is_verified_domain: bool
) -> Dict[str, Any]:
    """
    Layer 4 & 5: Contextual Suspicious Keyword System
    Does NOT blindly flag legitimate URLs containing 'login' on verified domains.
    Evaluates keyword location (hostname vs path vs query) and domain trust context.
    """
    unquoted_path = unquote(path).lower()
    unquoted_query = unquote(query).lower()
    hostname_lower = hostname.lower()

    found_in_host: List[str] = []
    found_in_path: List[str] = []
    found_in_query: List[str] = []
    categorized_matches: Dict[str, List[str]] = {cat: [] for cat in SUSPICIOUS_KEYWORDS}

    for category, keywords in SUSPICIOUS_KEYWORDS.items():
        for kw in keywords:
            pattern = r"(?:^|[^a-zA-Z0-9])" + re.escape(kw) + r"(?:$|[^a-zA-Z0-9])"

            if re.search(pattern, hostname_lower):
                found_in_host.append(kw)
                categorized_matches[category].append(kw)

            if re.search(pattern, unquoted_path):
                found_in_path.append(kw)
                categorized_matches[category].append(kw)

            if re.search(pattern, unquoted_query):
                found_in_query.append(kw)
                categorized_matches[category].append(kw)

    all_found = list(set(found_in_host + found_in_path + found_in_query))

    # Contextual evaluation:
    # A keyword in path on a verified domain (e.g. github.com/login) is NOT contextually suspicious.
    # A keyword in hostname (e.g. login-update-paypal.com) IS highly suspicious.
    # Multiple keywords in path on an unverified or unknown domain is suspicious.
    if is_verified_domain:
        is_contextually_suspicious = False
        threat_level = "BENIGN_CONTEXT"
    elif len(found_in_host) > 0:
        is_contextually_suspicious = True
        threat_level = "HOST_DECEPTION"
    elif len(all_found) >= 2:
        is_contextually_suspicious = True
        threat_level = "MULTIPLE_CREDENTIAL_LURES"
    elif len(found_in_path) > 0:
        # Single keyword in path on an unverified, generic domain
        is_contextually_suspicious = True
        threat_level = "PATH_CREDENTIAL_LURE"
    else:
        is_contextually_suspicious = False
        threat_level = "NONE"

    return {
        "total_count": len(all_found),
        "found_keywords": sorted(all_found),
        "found_in_host": sorted(list(set(found_in_host))),
        "found_in_path": sorted(list(set(found_in_path))),
        "found_in_query": sorted(list(set(found_in_query))),
        "categorized_matches": categorized_matches,
        "is_contextually_suspicious": is_contextually_suspicious,
        "threat_level": threat_level,
        "has_auth_keywords": len(categorized_matches["authentication"]) > 0,
        "has_account_keywords": len(categorized_matches["account"]) > 0,
        "has_financial_keywords": len(categorized_matches["financial"]) > 0,
        "has_urgency_keywords": len(categorized_matches["urgency"]) > 0,
    }


def extract_all_features(normalized_url: str, original_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Multi-layer comprehensive feature extraction engine.
    Extracts 35+ structural, lexical, host, path, query, and security features.
    """
    orig_url = original_url or normalized_url
    parsed = urlparse(normalized_url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    port = parsed.port

    # Layer 3: Domain Components via tldextract
    domain_info = parse_domain_components(hostname)
    registered_domain = domain_info["registered_domain"]
    domain_name = domain_info["domain"]
    subdomain = domain_info["subdomain"]
    tld = domain_info["tld"].lstrip(".").lower()

    # Legitimacy Check: Is this a known verified organization domain?
    is_known_legitimate = (
        hostname in VERIFIED_LEGITIMATE_DOMAINS
        or registered_domain in VERIFIED_LEGITIMATE_DOMAINS
        or any(registered_domain.endswith("." + vd) for vd in VERIFIED_LEGITIMATE_DOMAINS)
    )

    # Layer 4: IP Address & Obfuscation
    ip_data = detect_ip_address(hostname)
    is_ip = ip_data["has_ip"]
    has_punycode = "xn--" in hostname
    has_at_symbol = "@" in normalized_url or "@" in orig_url
    has_double_slash_path = "//" in path
    is_shortener = hostname in SHORTENER_DOMAINS or any(hostname.endswith("." + d) for d in SHORTENER_DOMAINS)
    is_suspicious_tld = tld in SUSPICIOUS_TLDS

    # Percent encoding
    percent_matches = re.findall(r"%[0-9a-fA-F]{2}", normalized_url)
    has_percent_encoding = len(percent_matches) > 0
    percent_encoding_count = len(percent_matches)

    # Port checking
    has_suspicious_port = bool(port and port not in STANDARD_PORTS)

    # Layer 5: Brand Impersonation Analysis
    userinfo_part = netloc.split("@")[0] if "@" in netloc else ("" if "@" not in orig_url else orig_url.split("@")[0].split("://")[-1])
    brand_data = detect_brand_impersonation(hostname, domain_info, path, userinfo=userinfo_part)

    # Layer 4 & 5: Contextual Keywords
    keywords_data = detect_suspicious_keywords_context(
        normalized_url, hostname, domain_info, path, query, is_known_legitimate or brand_data["is_brand_authorized"]
    )

    # Redirect Parameters
    redirect_data = analyze_redirect_parameters(query)

    # Entropy Calculations
    hostname_entropy = calculate_entropy(hostname)
    domain_entropy = calculate_entropy(domain_name)
    path_entropy = calculate_entropy(path)

    # Path Features
    path_segments = [p for p in path.split("/") if p]
    path_depth = len(path_segments)
    
    # File extension check
    file_ext = ""
    has_executable = False
    last_segment = path_segments[-1] if path_segments else ""
    if "." in last_segment:
        file_ext = "." + last_segment.split(".")[-1].lower()
        if file_ext in EXECUTABLE_EXTENSIONS:
            has_executable = True

    # Character counts & ratios
    url_len = len(normalized_url)
    special_set = set("!*'();:@&=+$,/?%#[]~_`^{}|\\-")
    special_count = sum(1 for c in normalized_url if c in special_set)
    digit_count = sum(1 for c in normalized_url if c.isdigit())
    domain_hyphens = hostname.count("-")
    domain_digits = sum(1 for c in hostname if c.isdigit())
    unusual_host_chars = sum(1 for c in hostname if c not in "abcdefghijklmnopqrstuvwxyz0123456789.-")

    digit_ratio = round(digit_count / url_len, 3) if url_len > 0 else 0.0
    special_char_ratio = round(special_count / url_len, 3) if url_len > 0 else 0.0

    features = {
        # General URL features
        "url_length": url_len,
        "hostname_length": len(hostname),
        "domain_length": len(domain_name),
        "path_length": len(path),
        "query_length": len(query),
        "fragment_length": len(fragment),
        "dot_count": normalized_url.count("."),
        "hyphen_count": normalized_url.count("-"),
        "underscore_count": normalized_url.count("_"),
        "slash_count": normalized_url.count("/"),
        "question_mark_count": normalized_url.count("?"),
        "equals_count": normalized_url.count("="),
        "ampersand_count": normalized_url.count("&"),
        "special_character_count": special_count,
        "digit_count": digit_count,
        "digit_ratio": digit_ratio,
        "special_char_ratio": special_char_ratio,

        # Hostname Features
        "subdomain_count": domain_info["subdomain_count"],
        "subdomain_length": domain_info["subdomain_length"],
        "hostname_entropy": hostname_entropy,
        "domain_entropy": domain_entropy,
        "has_high_domain_entropy": domain_entropy > 3.8 or hostname_entropy > 4.2,
        "domain_hyphen_count": domain_hyphens,
        "domain_digit_count": domain_digits,
        "domain_unusual_char_count": unusual_host_chars,
        "is_hyphen_heavy_domain": domain_hyphens >= 3,
        "has_long_hostname": len(hostname) > 30,

        # IP Detection
        "has_ip_address": is_ip,
        "is_ipv4": ip_data["is_ipv4"],
        "is_ipv6": ip_data["is_ipv6"],
        "is_decimal_ip": ip_data["is_decimal_ip"],
        "is_hex_ip": ip_data["is_hex_ip"],

        # Encoding & Spoofing
        "has_punycode": has_punycode,
        "has_percent_encoding": has_percent_encoding,
        "percent_encoding_count": percent_encoding_count,
        "has_at_symbol": has_at_symbol,
        "has_double_slash_path": has_double_slash_path,
        "has_url_shortener": is_shortener,
        "has_suspicious_tld": is_suspicious_tld,

        # Protocol & Port
        "has_https": (scheme == "https"),
        "has_http": (scheme == "http"),
        "has_suspicious_port": has_suspicious_port,
        "custom_port": port if has_suspicious_port else None,

        # Path & Query Features
        "path_depth": path_depth,
        "path_entropy": path_entropy,
        "file_extension": file_ext,
        "has_executable_extension": has_executable,
        "query_param_count": len(parse_qs(query)),
        "has_redirect_params": redirect_data["has_redirect_param"],
        "redirect_params_found": redirect_data["redirect_params"],
        "has_external_redirect_target": redirect_data["has_external_target"],
        "redirect_target_url": redirect_data["target_url"],

        # Brand Impersonation & Legitimacy
        "detected_brand": brand_data["detected_brand"],
        "is_brand_impersonation": brand_data["is_brand_impersonation"],
        "is_brand_authorized": brand_data["is_brand_authorized"],
        "brand_impersonation_location": brand_data["impersonation_location"],
        "is_known_legitimate_domain": is_known_legitimate,

        # Contextual Keywords
        "suspicious_keyword_count": keywords_data["total_count"],
        "found_keywords": keywords_data["found_keywords"],
        "keywords_in_host": keywords_data["found_in_host"],
        "keywords_in_path": keywords_data["found_in_path"],
        "keywords_in_query": keywords_data["found_in_query"],
        "is_contextually_suspicious": keywords_data["is_contextually_suspicious"],
        "keyword_threat_level": keywords_data["threat_level"],
        "has_login_keywords": keywords_data["has_auth_keywords"],
        "has_account_keywords": keywords_data["has_account_keywords"],
        "has_payment_keywords": keywords_data["has_financial_keywords"],
        "has_urgency_keywords": keywords_data["has_urgency_keywords"],
        "categorized_keywords": keywords_data["categorized_matches"],

        # Clean Domain Architecture for UI
        "domain_analysis": {
            "protocol": scheme.upper(),
            "hostname": hostname,
            "registered_domain": registered_domain,
            "domain": domain_name,
            "subdomain": subdomain,
            "tld": f".{tld}" if tld else "",
            "port": port if port else (443 if scheme == "https" else 80),
            "is_custom_port": has_suspicious_port,
            "path": path,
            "query": query,
            "query_parameters": list(parse_qs(query).keys()),
            "is_ip_based": is_ip,
            "is_shortener": is_shortener,
            "is_punycode": has_punycode,
            "is_brand_impersonation": brand_data["is_brand_impersonation"],
            "detected_brand": brand_data["detected_brand"],
            "is_known_legitimate": is_known_legitimate,
            "analysis_type": "Multi-Layer Pattern & Domain Analysis"
        }
    }

    return features
