import unittest
from unittest.mock import patch

from core.scanner import HostResult, PortInfo
from core.security_analyst import SecurityAnalyst
from core.vulnerability_sources import (
    VulnerabilitySources,
    canonicalize_cpe,
    has_concrete_cpe_version,
)


class FakeVulnerabilitySources:
    def __init__(self, records=None):
        self.records = records or []
        self.queried_cpes = []

    def get_kev_entries(self):
        return {}

    def get_cves_for_cpe(self, cpe):
        self.queried_cpes.append(cpe)
        return self.records

    def get_cve(self, cve_id):
        return None


class CveMatchingTests(unittest.TestCase):
    def test_converts_legacy_cpe_and_requires_concrete_version(self):
        legacy = "cpe:/a:apache:http_server:2.4.49"

        canonical = canonicalize_cpe(legacy)

        self.assertEqual(
            canonical,
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        )
        self.assertTrue(has_concrete_cpe_version(canonical))
        self.assertFalse(
            has_concrete_cpe_version("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")
        )

    def test_nvd_request_converts_legacy_cpe_and_uses_vulnerable_flag(self):
        source = VulnerabilitySources()
        with patch.object(
            source, "_nvd_query", return_value={"vulnerabilities": []}
        ) as nvd_query:
            source.get_cves_for_cpe("cpe:/a:apache:http_server:2.4.49")

        params = nvd_query.call_args.args[0]
        self.assertEqual(
            params["cpeName"],
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        )
        # NVD's endpoint treats isVulnerable as a presence flag; "true" returns 404.
        self.assertEqual(params["isVulnerable"], "")

    def test_exact_cpe_match_creates_candidate_not_confirmed_finding(self):
        cpe = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        nmap_cpe = "cpe:/a:apache:http_server:2.4.49"
        record = {
            "cve": {
                "id": "CVE-2021-41773",
                "descriptions": [{"lang": "en", "value": "Path traversal vulnerability"}],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}
                    }]
                },
            }
        }
        sources = FakeVulnerabilitySources([record])
        port = PortInfo(
            port=443,
            protocol="tcp",
            state="open",
            service="https",
            product="Apache httpd",
            version="2.4.49",
            extra_info="",
            cpes=[nmap_cpe],
        )
        host = HostResult(
            ip="192.0.2.10",
            hostname="web.lab",
            state="up",
            os_guess="Linux",
            ports=[port],
        )

        findings = SecurityAnalyst(sources=sources).analyze([host])

        cve_finding = next(item for item in findings if item.cve_id == "CVE-2021-41773")
        self.assertEqual(sources.queried_cpes, [cpe])
        self.assertEqual(cve_finding.status, "candidate")
        self.assertEqual(cve_finding.severity, "High")
        self.assertIn("no demuestra", cve_finding.evidence)


if __name__ == "__main__":
    unittest.main()
