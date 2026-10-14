"""NO_PROXY entries httpx cannot parse must not crash client construction.

Reported 2026-10-14: a VM whose no_proxy carried an IPv6 entry made every CLI
command fail with httpx.InvalidURL until the user ran `env -u no_proxy`.
"""

import os

import pytest

from twlegalrag.retrieval import TLRClient


@pytest.mark.parametrize("value", ["::1/128", "[::1]", "fe80::/10", "localhost,::1/128,10.0.0.0/8"])
def test_bad_ipv6_no_proxy_entries_do_not_crash(monkeypatch, capsys, value):
    monkeypatch.setenv("NO_PROXY", value)
    monkeypatch.setenv("no_proxy", value)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    with TLRClient():
        pass
    assert "ignoring NO_PROXY entries" in capsys.readouterr().err
    assert os.environ["NO_PROXY"] == value  # environment left untouched


def test_valid_no_proxy_is_silent(monkeypatch, capsys):
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1,::1,.internal")
    monkeypatch.delenv("no_proxy", raising=False)
    with TLRClient():
        pass
    assert capsys.readouterr().err == ""
