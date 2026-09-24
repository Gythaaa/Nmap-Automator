"""Typed response models and evidence-grounding checks for AI narratives."""

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError


CVE_TOKEN_PATTERN = re.compile(r"\bCVE-\d{4}-[A-Z0-9]+(?:-[A-Z0-9]+)*\b", re.IGNORECASE)
VALID_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
URL_PATTERN = re.compile(r"https?://\S+", re.IGNORECASE)


class FindingNarrativeOutput(BaseModel):
    """Schema for one generated explanation; references are IDs from retrieved evidence."""

    model_config = ConfigDict(extra="forbid")

    # Use an explicit digit class; some local constrained decoders do not support \d.
    id: str = Field(pattern=r"^F[0-9]{3}$")
    summary: str = Field(min_length=1, max_length=1600)
    impact: str = Field(min_length=1, max_length=1800)
    remediation: str = Field(min_length=1, max_length=1800)
    confidence: float = Field(ge=0, le=1)
    references: list[str] = Field(max_length=5)


class SecurityNarrativeOutput(BaseModel):
    """Validated structured response returned by an AI provider."""

    model_config = ConfigDict(extra="forbid")

    executive_summary: str = Field(max_length=2400)
    findings: list[FindingNarrativeOutput] = Field(max_length=30)


def validate_narrative_output(
    payload: Any,
    allowed_finding_ids: set[str],
    allowed_references: dict[str, set[str]],
    allowed_cves: dict[str, set[str]],
) -> SecurityNarrativeOutput:
    """Validate shape, finding identity, cited references, and CVEs against evidence."""
    try:
        output = SecurityNarrativeOutput.model_validate(payload)
    except ValidationError as exc:
        raise RuntimeError(f"La respuesta IA no cumple el esquema Pydantic: {exc}") from exc

    seen_ids: set[str] = set()
    all_known_cves = set().union(*allowed_cves.values()) if allowed_cves else set()
    _validate_claims(output.executive_summary, all_known_cves, "resumen ejecutivo")

    for item in output.findings:
        if item.id not in allowed_finding_ids:
            raise RuntimeError(f"La respuesta IA contiene un hallazgo desconocido: {item.id}.")
        if item.id in seen_ids:
            raise RuntimeError(f"La respuesta IA duplicó el hallazgo {item.id}.")
        seen_ids.add(item.id)

        unknown_references = set(item.references) - allowed_references.get(item.id, set())
        if unknown_references:
            raise RuntimeError(
                f"La respuesta IA citó referencias no recuperadas para {item.id}: "
                f"{', '.join(sorted(unknown_references))}."
            )

        allowed = allowed_cves.get(item.id, set())
        for text in (item.summary, item.impact, item.remediation):
            _validate_claims(text, allowed, f"hallazgo {item.id}")

    missing_ids = allowed_finding_ids - seen_ids
    if missing_ids:
        raise RuntimeError(
            "La respuesta IA omitió hallazgos que debía explicar: "
            f"{', '.join(sorted(missing_ids))}."
        )

    return output


def _validate_claims(text: str, allowed_cves: set[str], location: str) -> None:
    """Reject CVE identifiers or direct citations absent from the retrieved evidence."""
    mentioned_cves = {match.upper() for match in CVE_TOKEN_PATTERN.findall(text)}
    unsupported_cves = mentioned_cves - allowed_cves
    if unsupported_cves:
        raise RuntimeError(
            f"La respuesta IA mencionó CVE no presente en la evidencia para {location}: "
            f"{', '.join(sorted(unsupported_cves))}."
        )

    if URL_PATTERN.search(text):
        raise RuntimeError(
            f"La respuesta IA incluyó una URL no validada en {location}; "
            "debe citar referencias recuperadas por su ID."
        )


def pydantic_output_schema() -> dict[str, Any]:
    """Return the schema shared with providers that support constrained JSON output."""
    schema = SecurityNarrativeOutput.model_json_schema()
    definitions = schema.pop("$defs", {})
    item_schema = schema["properties"]["findings"]["items"]
    reference = item_schema.pop("$ref", "")
    definition_name = reference.rsplit("/", 1)[-1]
    if definition_name in definitions:
        schema["properties"]["findings"]["items"] = definitions[definition_name]
    return schema
