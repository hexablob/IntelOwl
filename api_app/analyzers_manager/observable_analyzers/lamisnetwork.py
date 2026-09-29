# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class LamisNetwork(classes.ObservableAnalyzer):
    """
    Lamis Network IP Intelligence Analyzer.
    Retrieves ASN, Datacenter/VPN/Tor status, and Fraud Score.
    """

    url: str = "https://api.lamisnetwork.com/v1/ip/"
    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        return True

    def run(self):
        try:
            response = requests.get(
                self.url + self.observable_name,
                headers={
                    "Authorization": f"Bearer {self._api_key_name}",
                    "Accept": "application/json",
                },
                timeout=15,
            )
            response.raise_for_status()
            result = response.json()
        except requests.RequestException as e:
            raise AnalyzerRunException(e) from e
        except ValueError as e:
            raise AnalyzerRunException(f"Invalid JSON response: {e}") from e

        return result
