"""
conftest.py — Secure Access Lab
Pytest configuration, markers, and shared fixtures.
"""
import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--runslow",
        action="store_true",
        default=False,
        help="Run slow tests (timer/delay-dependent)",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "sim: Phase 1 simulation test (no hardware)")
    config.addinivalue_line("markers", "slow: Test involves real timer delays")


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--runslow"):
        skip_slow = pytest.mark.skip(reason="Pass --runslow to run timer-dependent tests")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)
