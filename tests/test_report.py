import io
import tempfile
import unittest
from pathlib import Path

from rich.console import Console

from core.findings import FindingReference, SecurityFinding
from core.scanner import HostResult, PortInfo
from reports.pdf_report import PDFReportGenerator


class ReportTests(unittest.TestCase):
    def test_generates_pdf_with_ai_narrative_and_validated_reference(self):
        host = HostResult(
            ip="192.0.2.10",
            hostname="web.lab",
            state="up",
            os_guess="Linux",
            ports=[PortInfo(443, "tcp", "open", "https", "Apache", "2.4.49", "")],
        )
        finding = SecurityFinding(
            finding_id="CVE-2021-41773-192.0.2.10-443",
            title="CVE-2021-41773: path traversal",
            status="candidate",
            severity="High",
            confidence="Medium",
            host_ip=host.ip,
            hostname=host.hostname,
            port=443,
            protocol="tcp",
            service="https",
            product="Apache",
            version="2.4.49",
            evidence="Nmap CPE match; validate against vendor advisory.",
            impact="Possible path traversal.",
            remediation="Upgrade to a fixed version.",
            source="NVD CPE match",
            cve_id="CVE-2021-41773",
            references=[FindingReference(
                "NVD record",
                "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                "NVD",
            )],
            ai_generated=True,
            ai_provider="Analista de prueba",
            ai_summary="El activo requiere validar si el rango afectado aplica.",
            ai_confidence=0.84,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.pdf"
            generator = PDFReportGenerator(
                output_path=str(output_path),
                console=Console(file=io.StringIO()),
            )

            generator.generate(
                [host],
                mode="medium",
                targets=[host.ip],
                findings=[finding],
                ai_summary="Revisar el candidato identificado por CPE.",
            )

            self.assertTrue(output_path.is_file())
            self.assertGreater(output_path.stat().st_size, 500)
            self.assertTrue(output_path.read_bytes().startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
