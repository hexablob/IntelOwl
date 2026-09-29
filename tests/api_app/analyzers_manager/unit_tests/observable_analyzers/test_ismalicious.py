# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.ismalicious import IsMalicious
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse

# Trimmed /check response (enrichment=standard): categories live on each
# source row, whose threatClass defaults to "threat" when absent.
SAMPLE_REPORT = {
    "enrichmentLevel": "standard",
    "malicious": True,
    "riskScore": {"score": 80, "level": "critical"},
    "classification": {"primary": "c2"},
    "sources": [{"name": "feed-a", "category": "c2"}],
    "reputation": {"malicious": 1, "suspicious": 0, "harmless": 0, "undetected": 0},
}


class IsMaliciousTestCase(BaseAnalyzerTest):
    analyzer_class = IsMalicious

    @staticmethod
    def get_mocked_response():
        return patch(
            "api_app.analyzers_manager.observable_analyzers.ismalicious.requests.get",
            return_value=MockUpResponse(SAMPLE_REPORT, 200),
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "fake_api_key"}
