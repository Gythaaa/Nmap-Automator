import unittest

from core.scanner import HostResult, PortInfo
from core.security_analyst import SecurityAnalyst


class EmptySources:
    def get_kev_entries(self):
        return {}

    def get_cves_for_cpe(self, cpe):
        return []

    def get_cve(self, cve_id):
        return None


class FindingClassificationTests(unittest.TestCase):
    def test_telnet_is_an_exposure_observation(self):
        port = PortInfo(23, "tcp", "open", "telnet", "", "", "")
        host = HostResult("192.0.2.5", "lab", "up", "Linux", ports=[port])

        findings = SecurityAnalyst(sources=EmptySources()).analyze([host])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "exposure")
        self.assertEqual(findings[0].severity, "Informational")

    def test_explicit_positive_nse_result_is_confirmed(self):
        host = HostResult(
            "192.0.2.5",
            "lab",
            "up",
            "Linux",
            vuln_scripts=[{"id": "http-vuln-test", "output": "VULNERABLE: test condition"}],
        )

        findings = SecurityAnalyst(sources=EmptySources()).analyze([host])

        self.assertEqual(findings[0].status, "confirmed")
        self.assertEqual(findings[0].source, "Nmap NSE")

    def test_negative_nse_result_does_not_create_finding(self):
        host = HostResult(
            "192.0.2.5",
            "lab",
            "up",
            "Linux",
            vuln_scripts=[{"id": "http-vuln-test", "output": "NOT VULNERABLE"}],
        )

        findings = SecurityAnalyst(sources=EmptySources()).analyze([host])

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
