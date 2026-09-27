import pytest
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from detection.feature_extractor import extract_all_features, normalize_url
from detection.risk_engine import calculate_risk
from detection.classifier import classifier_instance


LEGITIMATE_TEST_URLS = [
    "https://www.google.com",
    "https://google.com/search?q=cybersecurity+defense",
    "https://accounts.google.com/signin/v2/identifier",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://github.com",
    "https://github.com/login",
    "https://github.com/explore",
    "https://github.com/settings/security",
    "https://www.microsoft.com/en-us/software-download",
    "https://login.microsoftonline.com/common/oauth2/authorize",
    "https://account.microsoft.com/security",
    "https://www.apple.com/iphone-15",
    "https://appleid.apple.com/sign-in",
    "https://support.apple.com/billing",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://en.wikipedia.org/wiki/Computer_security",
    "https://www.amazon.com/gp/bestsellers",
    "https://www.amazon.com/ap/signin",
    "https://stackoverflow.com/questions",
    "https://stackoverflow.com/users/login",
]

SUSPICIOUS_TEST_URLS = [
    "http://bit.ly/meeting-notes-review",
    "http://tinyurl.com/project-brief-2026",
    "http://is.gd/team-schedule-july",
    "http://ow.ly/weekly-newsletter-doc",
    "http://t.co/event-registration-open",
    "http://cutt.ly/press-release-q3",
    "http://rebrand.ly/annual-report-pdf",
    "http://rb.gy/tech-symposium-info",
    "https://app-redirect.top/link?redirect=https://external-target.org",
    "https://service-gateway.click/redirect?url=https://other-site.com",
    "http://simple-weather-app.buzz:8080/city/london",
    "http://test-server-instance.loan:8080/metrics",
    "http://developer-sandbox.fit:8080/preview",
    "http://temporary-mirror.rest:8080/manual",
    "http://staging-service.quest:8080/status",
    "http://analytics-collector.live:8080/events/token",
    "http://backup-storage.uno:8080/files",
    "http://cluster-status.cfd:8080/health",
    "http://node-monitor.country:8080/ping",
    "http://sensor-data.casa:8080/stream",
]

SYNTHETIC_PHISHING_URLS = [
    "http://192.168.1.100/login/bank-verify.html",
    "http://10.0.0.1/admin/secure/signin.php",
    "http://84.17.45.12/webscr?cmd=_login-run&dispatch=verify",
    "http://198.51.100.24:8080/account/login.php",
    "http://0x7f.0x0.0x0.0x1/chase-online-login.html",
    "http://2130706433/paypal-verification-center",
    "https://paypal.com.verify-account-center.xyz/login",
    "https://paypal-security-update-center-login.xyz/confirm",
    "http://chase-bank-online-alert.top/verify-identity",
    "http://chase.com.account-verification-notice.click/signin",
    "http://bankofamerica.com-secure-signin.club/update",
    "http://apple-id-verify.support-device.icu/unlock",
    "http://appleid-security-account-locked.xyz/recover",
    "https://microsoft-office365-login.work/auth/session",
    "https://microsoftonline.security-verify.live/session-token",
    "https://netflix-subscription-renew.loan/billing/card",
    "http://user:pass@evil-phishing-host.xyz/login",
    "http://login.paypal.com@attacker-site.org/signin",
    "http://www.xn--googl-fsa.com/search",
    "http://d94j2k8snf01a.buzz/invoice/download.exe",
]


def test_twenty_legitimate_urls_classified_as_safe():
    """
    Verifies that all 20 legitimate URLs (including /login and /auth on known domains)
    score within the SAFE threshold (<= 29). Zero false positives.
    """
    assert len(LEGITIMATE_TEST_URLS) == 20

    for url in LEGITIMATE_TEST_URLS:
        orig, norm, valid, _ = normalize_url(url)
        assert valid is True
        features = extract_all_features(norm, original_url=orig)
        ml_res = classifier_instance.predict(features)
        risk = calculate_risk(features, ml_result=ml_res)

        assert risk["classification"] == "SAFE", (
            f"False Positive on legitimate URL '{url}': "
            f"score={risk['risk_score']}, indicators={[i['name'] for i in risk['indicators']]}"
        )
        assert risk["risk_score"] <= 29
        assert risk["confidence"] >= 0.80


def test_twenty_suspicious_urls_classified_as_suspicious():
    """
    Verifies that all 20 suspicious URLs score in the SUSPICIOUS range (30-59).
    """
    assert len(SUSPICIOUS_TEST_URLS) == 20

    for url in SUSPICIOUS_TEST_URLS:
        orig, norm, valid, _ = normalize_url(url)
        assert valid is True
        features = extract_all_features(norm, original_url=orig)
        ml_res = classifier_instance.predict(features)
        risk = calculate_risk(features, ml_result=ml_res)

        assert risk["classification"] == "SUSPICIOUS", (
            f"Expected SUSPICIOUS for '{url}', got '{risk['classification']}' (score={risk['risk_score']})"
        )
        assert 30 <= risk["risk_score"] <= 59


def test_twenty_synthetic_phishing_urls_classified_as_potential_phishing():
    """
    Verifies that all 20 synthetic phishing URLs score in the high-threat range (>= 60).
    Zero false negatives on blatant phishing vectors.
    """
    assert len(SYNTHETIC_PHISHING_URLS) == 20

    for url in SYNTHETIC_PHISHING_URLS:
        orig, norm, valid, _ = normalize_url(url)
        assert valid is True
        features = extract_all_features(norm, original_url=orig)
        ml_res = classifier_instance.predict(features)
        risk = calculate_risk(features, ml_result=ml_res)

        assert risk["classification"] == "POTENTIAL_PHISHING", (
            f"False Negative on synthetic phishing URL '{url}': "
            f"score={risk['risk_score']}, classification={risk['classification']}"
        )
        assert risk["risk_score"] >= 60
        assert risk["confidence"] >= 0.85
        assert len(risk["indicators"]) > 0


def test_github_login_false_positive_elimination():
    """
    Crucial check: https://github.com/login must NOT be classified as Phishing or Suspicious.
    """
    orig, norm, valid, _ = normalize_url("https://github.com/login")
    features = extract_all_features(norm, original_url=orig)
    ml_res = classifier_instance.predict(features)
    risk = calculate_risk(features, ml_result=ml_res)

    assert risk["classification"] == "SAFE"
    assert risk["risk_score"] < 15
    # Contextual keywords rule should not trigger for github.com
    rule_ids = [i["rule_id"] for i in risk["indicators"]]
    assert "contextual_keywords" not in rule_ids
    assert "brand_impersonation" not in rule_ids


def test_brand_impersonation_detection_chase_and_paypal():
    orig, norm, _, _ = normalize_url("https://paypal.com.verify-account-center.xyz/login")
    features = extract_all_features(norm, original_url=orig)
    ml_res = classifier_instance.predict(features)
    risk = calculate_risk(features, ml_result=ml_res)

    assert risk["classification"] == "POTENTIAL_PHISHING"
    rule_ids = [i["rule_id"] for i in risk["indicators"]]
    assert "brand_impersonation" in rule_ids
    assert "suspicious_tld" in rule_ids
