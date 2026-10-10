import pytest

from app.risk import calculate_priority_score


def test_priority_score_is_bounded():
    for severity in ("critical", "high", "medium", "low", "info", "unknown"):
        score = calculate_priority_score(severity, "high")
        assert 0 <= score <= 100


def test_higher_severity_has_higher_priority_for_same_context():
    values = [calculate_priority_score(level, "high") for level in ("info", "low", "medium", "high", "critical")]
    assert values == sorted(values)
    assert len(set(values)) == len(values)


def test_confidence_and_bounds_are_applied():
    assert calculate_priority_score("high", "high") > calculate_priority_score("high", "low")
    with pytest.raises(ValueError):
        calculate_priority_score("high", "high", exposure=101)
