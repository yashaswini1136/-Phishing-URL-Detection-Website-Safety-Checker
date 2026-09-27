import pytest
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from detection.classifier import FEATURE_NAMES, classifier_instance, extract_feature_vector
from detection.feature_extractor import extract_all_features, normalize_url


def test_classifier_is_loaded():
    assert classifier_instance.is_loaded is True
    assert classifier_instance.model is not None
    assert classifier_instance.scaler is not None
    assert len(FEATURE_NAMES) == 42


def test_feature_vector_dimension():
    orig, norm, _, _ = normalize_url("https://example.com/test")
    features = extract_all_features(norm, original_url=orig)
    vec = extract_feature_vector(features)
    assert len(vec) == len(FEATURE_NAMES)
    assert isinstance(vec, list)
    for val in vec:
        assert isinstance(val, (int, float))


def test_classifier_prediction_legitimate():
    orig, norm, _, _ = normalize_url("https://www.google.com")
    features = extract_all_features(norm, original_url=orig)
    res = classifier_instance.predict(features)

    assert res["ml_available"] is True
    assert res["detection_method"] == "Hybrid Rule + ML Analysis"
    assert res["ml_phishing_probability"] is not None
    assert res["ml_phishing_probability"] < 0.3
    assert res["ml_prediction"] == "LEGITIMATE"


def test_classifier_prediction_phishing():
    orig, norm, _, _ = normalize_url("http://192.168.1.100/login/bank-verify.html")
    features = extract_all_features(norm, original_url=orig)
    res = classifier_instance.predict(features)

    assert res["ml_available"] is True
    assert res["ml_phishing_probability"] is not None
    assert res["ml_phishing_probability"] > 0.7
    assert res["ml_prediction"] == "POTENTIAL_PHISHING"
