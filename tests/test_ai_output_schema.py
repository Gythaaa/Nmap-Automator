import json
import unittest

from core.ai_schemas import pydantic_output_schema
from core.findings import FindingReference, SecurityFinding
from core.security_analyst import SecurityNarrativeAnalyst


def make_finding():
    return SecurityFinding(
        finding_id="CVE-2021-41773-192.0.2.10-443",
        title="CVE-2021-41773: path traversal",
        status="candidate",
        severity="High",
        confidence="Medium",
        host_ip="192.0.2.10",
        hostname="web.lab",
        port=443,
        protocol="tcp",
        service="https",
        product="Apache httpd",
        version="2.4.49",
        evidence=(
            "Nmap identified Apache on web.lab (192.0.2.10). "
            "NVD associates CVE-2021-41773 with this CPE."
        ),
        impact="Path traversal may expose files.",
        remediation="Upgrade to a fixed release.",
        source="NVD CPE match",
        cve_id="CVE-2021-41773",
        references=[FindingReference(
            title="NVD record",
            url="https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
            source="NVD",
        )],
    )


def valid_payload():
    return {
        "executive_summary": "Se identificó un candidato CVE que requiere validación.",
        "findings": [{
            "id": "F001",
            "summary": "Apache coincide con el candidato CVE recuperado.",
            "impact": "CVE-2021-41773 podría permitir traversal si se cumplen las condiciones afectadas.",
            "remediation": "Revisar el advisory y actualizar Apache a una versión corregida.",
            "confidence": 0.91,
            "references": ["F001-R001"],
        }],
    }


class StaticAnalyst(SecurityNarrativeAnalyst):
    provider = "Analista de prueba"

    def __init__(self, payload, share_target_identifiers=False):
        super().__init__("modelo-de-prueba", share_target_identifiers)
        self.payload = payload
        self.sent_prompt = ""

    def _complete(self, system_prompt, user_prompt, schema):
        self.sent_prompt = user_prompt
        return json.dumps(self.payload)


class RawResponseAnalyst(SecurityNarrativeAnalyst):
    provider = "Analista de prueba"

    def __init__(self, response):
        super().__init__("modelo-de-prueba")
        self.response = response

    def _complete(self, system_prompt, user_prompt, schema):
        return self.response


class AiOutputSchemaTests(unittest.TestCase):
    def test_valid_output_is_typed_and_maps_to_original_finding(self):
        finding = make_finding()
        analyst = StaticAnalyst(valid_payload())

        summary, narratives = analyst.generate([finding])

        self.assertIn("candidato", summary)
        narrative = narratives[finding.finding_id]
        self.assertEqual(narrative["summary"], valid_payload()["findings"][0]["summary"])
        self.assertEqual(narrative["confidence"], 0.91)

    def test_normalizes_percentage_confidence_from_model(self):
        payload = valid_payload()
        payload["findings"][0]["confidence"] = 85

        _, narratives = StaticAnalyst(payload).generate([make_finding()])

        self.assertEqual(narratives[make_finding().finding_id]["confidence"], 0.85)

    def test_accepts_fractional_confidence_without_rescaling(self):
        payload = valid_payload()
        payload["findings"][0]["confidence"] = 0.85

        _, narratives = StaticAnalyst(payload).generate([make_finding()])

        self.assertEqual(narratives[make_finding().finding_id]["confidence"], 0.85)

    def test_model_receives_only_reference_ids_not_titles_or_urls(self):
        finding = make_finding()
        analyst = StaticAnalyst(valid_payload())

        analyst.generate([finding])

        self.assertIn('"reference_ids": ["F001-R001"]', analyst.sent_prompt)
        self.assertNotIn("NVD record", analyst.sent_prompt)
        self.assertNotIn(finding.references[0].url, analyst.sent_prompt)
        self.assertIn("NUNCA devuelvas títulos, URLs ni nombres de archivo", analyst.sent_prompt)

    def test_logs_truncated_raw_model_payload_when_response_is_rejected(self):
        response = "not-json-debug-marker" + ("x" * 4000)

        with self.assertLogs("nmap_automator.ai", level="DEBUG") as captured:
            with self.assertRaises(RuntimeError):
                RawResponseAnalyst(response).generate([make_finding()])

        logged_message = captured.records[0].getMessage()
        logged_payload = logged_message.partition("): ")[2]
        self.assertIn("Payload crudo del modelo", logged_message)
        self.assertTrue(logged_payload.startswith("not-json-debug-marker"))
        self.assertEqual(len(logged_payload), 3000)

    def test_target_identifiers_are_redacted_by_default(self):
        finding = make_finding()
        analyst = StaticAnalyst(valid_payload())

        analyst.generate([finding])

        self.assertNotIn("192.0.2.10", analyst.sent_prompt)
        self.assertNotIn("web.lab", analyst.sent_prompt)
        self.assertIn("[HOST]", analyst.sent_prompt)

    def test_target_identifiers_are_only_included_with_opt_in(self):
        finding = make_finding()
        analyst = StaticAnalyst(valid_payload(), share_target_identifiers=True)

        analyst.generate([finding])

        self.assertIn("192.0.2.10", analyst.sent_prompt)
        self.assertIn("web.lab", analyst.sent_prompt)

    def test_rejects_cve_absent_from_retrieved_evidence(self):
        payload = valid_payload()
        payload["findings"][0]["impact"] = "CVE-2026-XXXX is exploitable."

        with self.assertRaisesRegex(RuntimeError, "CVE no presente"):
            StaticAnalyst(payload).generate([make_finding()])

    def test_rejects_reference_id_absent_from_retrieved_evidence(self):
        payload = valid_payload()
        payload["findings"][0]["references"] = ["F001-R999"]

        with self.assertRaisesRegex(RuntimeError, "referencias no recuperadas"):
            StaticAnalyst(payload).generate([make_finding()])

    def test_rejects_response_that_does_not_match_pydantic_schema(self):
        payload = valid_payload()
        del payload["findings"][0]["confidence"]

        with self.assertRaisesRegex(RuntimeError, "esquema Pydantic"):
            StaticAnalyst(payload).generate([make_finding()])

    def test_schema_forbids_untyped_extra_properties(self):
        schema = pydantic_output_schema()

        self.assertFalse(schema["additionalProperties"])
        self.assertFalse(schema["properties"]["findings"]["items"]["additionalProperties"])

    def test_finding_id_pattern_uses_ascii_digit_class_for_local_decoders(self):
        schema = pydantic_output_schema()

        pattern = schema["properties"]["findings"]["items"]["properties"]["id"]["pattern"]
        self.assertEqual(pattern, r"^F[0-9]{3}$")


if __name__ == "__main__":
    unittest.main()
