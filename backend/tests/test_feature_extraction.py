import pytest
import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from detection.feature_extractor import (
    analyze_redirect_parameters,
    calculate_entropy,
    detect_brand_impersonation,
    detect_ip_address,
    detect_suspicious_keywords_context,
    extract_all_features,
    normalize_url,
    parse_domain_components,
)


def test_url_normalization_preserves_original():
    orig, norm, valid, err = normalize_url("HTTPS://Example.COM:443/Login/Path?q=1#top")
    assert valid is True
    assert orig == "HTTPS://Example.COM:443/Login/Path?q=1#top"
    assert norm.startswith("https://example.com:443/Login/Path")
    assert err is None


def test_url_normalization_missing_scheme():
    orig, norm, valid, err = normalize_url("github.com/login")
    assert valid is True
    assert norm == "http://github.com/login"


def test_url_normalization_invalid_spaces():
    _, _, valid, err = normalize_url("https://bad space.com")
    assert valid is False
    assert "spaces" in err.lower()


def test_entropy_calculation():
    # Normal repetitive string should have low entropy
    low_ent = calculate_entropy("aaaaaa")
    assert low_ent == 0.0

    # Normal brand name
    brand_ent = calculate_entropy("google")
    assert 1.5 < brand_ent < 2.5

    # High randomness DGA string
    dga_ent = calculate_entropy("x8k3m9q2z7w4b1c")
    assert dga_ent > 3.5


def test_ip_address_detection_all_types():
    # Standard IPv4
    assert detect_ip_address("192.168.1.1")["has_ip"] is True
    assert detect_ip_address("192.168.1.1")["is_ipv4"] is True

    # Standard IPv6
    assert detect_ip_address("[2001:db8::1]")["has_ip"] is True
    assert detect_ip_address("[2001:db8::1]")["is_ipv6"] is True

    # Hexadecimal IP
    assert detect_ip_address("0x7f.0x0.0x0.0x1")["has_ip"] is True
    assert detect_ip_address("0x7f.0x0.0x0.0x1")["is_hex_ip"] is True

    # Decimal integer IP
    assert detect_ip_address("2130706433")["has_ip"] is True
    assert detect_ip_address("2130706433")["is_decimal_ip"] is True

    # Standard domain (non-IP)
    assert detect_ip_address("github.com")["has_ip"] is False


def test_tldextract_domain_parsing():
    parsed = parse_domain_components("login.security.example.co.uk")
    assert parsed["subdomain"] == "login.security"
    assert parsed["subdomain_count"] == 2
    assert parsed["domain"] == "example"
    assert parsed["tld"] == "co.uk"
    assert parsed["registered_domain"] == "example.co.uk"


def test_brand_impersonation_detection():
    # Impersonation: brand in registered domain
    domain_info_phish = {"registered_domain": "paypal-security-update.xyz", "subdomain": "login"}
    res1 = detect_brand_impersonation("paypal-security-update.xyz", domain_info_phish, "/login")
    assert res1["is_brand_impersonation"] is True
    assert res1["detected_brand"] == "paypal"
    assert res1["is_brand_authorized"] is False

    # Impersonation: brand in subdomain
    domain_info_sub = {"registered_domain": "attacker-spoof.com", "subdomain": "paypal.verify"}
    res2 = detect_brand_impersonation("paypal.verify.attacker-spoof.com", domain_info_sub, "/")
    assert res2["is_brand_impersonation"] is True
    assert res2["impersonation_location"] == "subdomain"

    # Authorized Brand Domain (e.g., paypal.com)
    domain_info_auth = {"registered_domain": "paypal.com", "subdomain": "www"}
    res3 = detect_brand_impersonation("www.paypal.com", domain_info_auth, "/signin")
    assert res3["is_brand_impersonation"] is False
    assert res3["is_brand_authorized"] is True


def test_redirect_parameter_detection():
    res = analyze_redirect_parameters("redirect=https://evil-phish.com/harvest&session=123")
    assert res["has_redirect_param"] is True
    assert res["has_external_target"] is True
    assert res["target_url"] == "https://evil-phish.com/harvest"

    # Benign internal parameter
    res2 = analyze_redirect_parameters("tab=dashboard&sort=desc")
    assert res2["has_redirect_param"] is False
    assert res2["has_external_target"] is False


def test_contextual_keywords_benign_vs_suspicious():
    # Benign: github.com/login on verified domain
    domain_info_gh = {"registered_domain": "github.com", "subdomain": ""}
    kw_benign = detect_suspicious_keywords_context(
        "https://github.com/login", "github.com", domain_info_gh, "/login", "", is_verified_domain=True
    )
    assert kw_benign["is_contextually_suspicious"] is False
    assert kw_benign["threat_level"] == "BENIGN_CONTEXT"

    # Suspicious: unknown domain with host deception
    domain_info_phish = {"registered_domain": "login-verify-account.xyz", "subdomain": ""}
    kw_phish = detect_suspicious_keywords_context(
        "http://login-verify-account.xyz", "login-verify-account.xyz", domain_info_phish, "/", "", is_verified_domain=False
    )
    assert kw_phish["is_contextually_suspicious"] is True
    assert kw_phish["threat_level"] == "HOST_DECEPTION"


def test_extract_all_features_structure():
    url = "https://paypal-update.xyz:8080/account/download.exe?redirect=http://external.com"
    feat = extract_all_features(url)

    assert feat["has_executable_extension"] is True
    assert feat["file_extension"] == ".exe"
    assert feat["has_suspicious_port"] is True
    assert feat["custom_port"] == 8080
    assert feat["has_suspicious_tld"] is True
    assert feat["is_brand_impersonation"] is True
    assert feat["detected_brand"] == "paypal"
    assert feat["has_external_redirect_target"] is True
    assert "domain_analysis" in feat
