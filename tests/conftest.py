from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


def classes(findings, vuln_class):
    return [f for f in findings if f.vuln_class == vuln_class]
