import pytest
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from detection.rules import (
    BrandImpersonationRule,
    IPAddressRule,
    AtSymbolRule,
    PunycodeRule,
    ExecutableDownloadRule,
    OpenRedirectRule,
    URLShortenerRule,
    ExcessiveSubdomainsRule,
    SuspiciousTLDRule,
    DomainEntropyRule,
    ContextualKeywordsRule,
    get_all_rules,
)


def test_brand_impersonation_rule():
    rule = BrandImpersonationRule()
    # Triggered
    res_trig = rule.evaluate({"is_brand_impersonation": True, "detected_brand": "paypal", "brand_impersonation_location": "registered_domain"})
    assert res_trig["triggered"] is True
    assert res_trig["score"] == 25
    assert "paypal" in res_trig["detail"]

    # Not triggered
    res_clean = rule.evaluate({"is_brand_impersonation": False})
    assert res_clean["triggered"] is False
    assert res_clean["score"] == 0


def test_ip_address_rule():
    rule = IPAddressRule()
    res = rule.evaluate({"has_ip_address": True, "is_ipv4": True})
    assert res["triggered"] is True
    assert res["score"] == 25


def test_at_symbol_rule():
    rule = AtSymbolRule()
    res = rule.evaluate({"has_at_symbol": True})
    assert res["triggered"] is True
    assert res["score"] == 25


def test_punycode_rule():
    rule = PunycodeRule()
    res = rule.evaluate({"has_punycode": True})
    assert res["triggered"] is True
    assert res["score"] == 20


def test_executable_rule():
    rule = ExecutableDownloadRule()
    res = rule.evaluate({"has_executable_extension": True, "file_extension": ".scr"})
    assert res["triggered"] is True
    assert res["score"] == 25
    assert ".scr" in res["detail"]


def test_open_redirect_rule():
    rule = OpenRedirectRule()
    res = rule.evaluate({"has_external_redirect_target": True, "redirect_target_url": "https://evil.com"})
    assert res["triggered"] is True
    assert res["score"] == 15


def test_domain_entropy_rule():
    rule = DomainEntropyRule()
    res = rule.evaluate({"has_high_domain_entropy": True, "domain_entropy": 4.1, "hostname_entropy": 4.3})
    assert res["triggered"] is True
    assert res["score"] == 12


def test_contextual_keywords_rule():
    rule = ContextualKeywordsRule()
    # Host deception
    res_host = rule.evaluate({
        "is_contextually_suspicious": True,
        "keywords_in_host": ["login", "verify"],
        "keywords_in_path": [],
        "keyword_threat_level": "HOST_DECEPTION"
    })
    assert res_host["triggered"] is True
    assert res_host["score"] == 15

    # Benign context (github.com/login)
    res_benign = rule.evaluate({
        "is_contextually_suspicious": False,
        "keywords_in_host": [],
        "keywords_in_path": ["login"],
        "keyword_threat_level": "BENIGN_CONTEXT"
    })
    assert res_benign["triggered"] is False
    assert res_benign["score"] == 0


def test_get_all_rules_count():
    rules = get_all_rules()
    assert len(rules) >= 15
    for r in rules:
        assert r.weight > 0
        assert r.severity in ("HIGH", "MEDIUM", "LOW", "CRITICAL")
