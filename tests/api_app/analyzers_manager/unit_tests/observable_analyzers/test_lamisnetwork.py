# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.lamisnetwork import LamisNetwork
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class LamisNetworkTestCase(BaseAnalyzerTest):
    analyzer_class = LamisNetwork

    @staticmethod
    def get_mocked_response():
        mock_response = {
            "ip": "8.8.8.8",
            "asn": {
                "asn": "AS15169",
                "name": "Google LLC",
                "domain": "google.com",
                "route": "8.8.8.0/24",
                "type": "hosting",
            },
            "is_vpn": False,
            "is_tor": False,
            "is_proxy": False,
            "is_datacenter": True,
            "fraud_score": 0,
        }
        return patch("requests.get", return_value=MockUpResponse(mock_response, 200))

    @classmethod
    def get_extra_config(cls) -> dict:
        return {"_api_key_name": "dummy_token"}
