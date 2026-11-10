import pytest

from app import rdap


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Tests never call real RDAP: fast, deterministic, works offline.
    Individual tests override this with the answer they need."""
    monkeypatch.setattr(rdap, "registration_date", lambda domain: None)
