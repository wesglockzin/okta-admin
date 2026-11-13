import pytest

from guards import is_allowed, origin_ok, safe_next


@pytest.mark.parametrize("target", ["/", "/logs", "/clear-progress?env=a&x=1"])
def test_safe_next_accepts_relative_paths(target):
    assert safe_next(target) == target


@pytest.mark.parametrize(
    "target",
    [
        None,
        "",
        "//evil.example.test",
        "//evil.example.test/path",
        "https://evil.example.test",
        "http:/evil.example.test",
        "/\\evil.example.test",
        "evil.example.test",
        "/ok\r\nSet-Cookie: x=1",
        "javascript:alert(1)",
    ],
)
def test_safe_next_rejects_everything_else(target):
    assert safe_next(target) is None


def test_is_allowed_matches_case_insensitively():
    allowed = frozenset({"a@example.test"})
    assert is_allowed(" A@Example.test ", allowed)
    assert not is_allowed("b@example.test", allowed)
    assert not is_allowed(None, allowed)
    assert not is_allowed("a@example.test", frozenset())


def test_origin_ok_same_site():
    host = "https://app.example.test/"
    assert origin_ok("https://app.example.test", None, host)
    assert origin_ok(None, "https://app.example.test/page", host)


def test_origin_ok_rejects_other_or_missing():
    host = "https://app.example.test/"
    assert not origin_ok("https://evil.example.test", None, host)
    assert not origin_ok("null", None, host)
    assert not origin_ok(None, None, host)
    assert not origin_ok("http://app.example.test", None, host)
