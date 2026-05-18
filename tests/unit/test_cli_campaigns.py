"""Tests for the campaign playbook structure (Phase 6).

Doesn't fire any attacks — just verifies the four playbooks are well-formed
and that `Campaign.expected_ttps` aggregates correctly across steps.
"""

from __future__ import annotations

import pytest

from honeystrike.cli.attack import campaigns


@pytest.mark.parametrize("name", ["apt28", "fin7", "ransomware-deployer", "script-kiddie"])
def test_each_playbook_yields_a_non_empty_campaign(name: str) -> None:
    builder = campaigns._PLAYBOOKS[name]
    campaign = builder("198.51.100.10")
    assert campaign.name == name
    assert campaign.steps
    for step in campaign.steps:
        assert step.runner is not None
        assert isinstance(step.kwargs, dict)
        assert isinstance(step.expected_ttps, tuple)


def test_apt28_expected_ttps_cover_brute_and_exploit() -> None:
    apt = campaigns._PLAYBOOKS["apt28"]("198.51.100.10")
    assert {"T1110.001", "T1190", "T1078"} <= set(apt.expected_ttps)


def test_script_kiddie_expects_no_ttps() -> None:
    sk = campaigns._PLAYBOOKS["script-kiddie"]("198.51.100.10")
    # Used as a low-noise baseline; deliberately should not raise TTPs.
    assert sk.expected_ttps == tuple()


def test_unknown_playbook_raises() -> None:
    with pytest.raises(KeyError):
        campaigns._PLAYBOOKS["does-not-exist"]("198.51.100.10")
