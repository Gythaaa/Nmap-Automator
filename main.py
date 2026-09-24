#!/usr/bin/env python3
"""
NmapAutomator - Herramienta de automatización de escaneo Nmap con interfaz Rich
Autor: Mau | Cybersecurity Toolset
"""

import os
import typer
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from core.scanner import NmapScanner
from core.metasploit_mapper import MetasploitMapper
from core.security_analyst import (
    AI_PROVIDER_LABELS,
    SecurityAnalyst,
    create_narrative_analyst,
)
from reports.pdf_report import PDFReportGenerator
from utils.app_logging import log_exception_to_file
from utils.ui import print_banner, print_summary_table, confirm_scan
from utils.validators import validate_targets

# ── Instancias globales ────────────────────────────────────────────────────────
app = typer.Typer(
    name="nmap-automator",
    help="[bold cyan]Herramienta de automatización Nmap con reporting PDF y sugerencias Metasploit[/]",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()


def _is_local_ollama_endpoint(url: str) -> bool:
    """Treat loopback endpoints as local; other Ollama URLs need external-data consent."""
    from ipaddress import ip_address
    from urllib.parse import urlsplit

    try:
        hostname = urlsplit(url).hostname
        if not hostname:
            return False
        try:
            return ip_address(hostname).is_loopback
        except ValueError:
            return hostname.casefold().rstrip(".") == "localhost"
    except ValueError:
        return False


# ── Comando principal ──────────────────────────────────────────────────────────
@app.command()
def scan(
    target: Optional[str] = typer.Option(
        None, "--target", "-t",
        help="IP, rango CIDR o hostname. Ej: 192.168.1.1 | 192.168.1.0/24",
    ),
    target_file: Optional[Path] = typer.Option(
        None, "--file", "-f",
        help="Archivo .txt con una IP/rango por línea.",
        exists=True, readable=True,
    ),
    ports: str = typer.Option(
        "1-1000", "--ports", "-p",
        help="Rango de puertos. Ej: 22,80,443 | 1-65535 | default",
    ),
    mode: str = typer.Option(
        "basic", "--mode", "-m",
        help="Modo de escaneo: [bold]basic[/] | [bold]medium[/] | [bold]extreme[/]",
    ),
    output: Path = typer.Option(
        Path("output/reporte_nmap.pdf"), "--output", "-o",
        help="Ruta del reporte PDF de salida.",
    ),
    no_confirm: bool = typer.Option(
        False, "--yes", "-y",
        help="Omitir confirmación antes de escanear.",
    ),
    security_analysis: bool = typer.Option(
        False, "--security-analysis",
        help="Consultar NVD y CISA KEV para correlacionar versiones/CPE y scripts NSE.",
    ),
    ai: bool = typer.Option(
        False, "--ai",
        help="Añadir narrativa de IA (implica --security-analysis).",
    ),
    ai_provider: Optional[str] = typer.Option(
        None, "--ai-provider",
        help="Proveedor para la narrativa IA: ollama, openai, claude, gemini o qwen. Implica --ai.",
    ),
    ai_model: Optional[str] = typer.Option(
        None, "--ai-model",
        help="Sobrescribir el modelo predeterminado del proveedor IA seleccionado.",
    ),
    allow_cloud_ai: bool = typer.Option(
        False, "--allow-cloud-ai",
        help="Consentir el envío de hallazgos técnicos a un proveedor o endpoint externo.",
    ),
    share_target_identifiers: bool = typer.Option(
        False, "--share-target-identifiers",
        help="Consentir incluir IP y hostname en la petición de narrativa IA.",
    ),
):
    """
    [bold green]Lanza un escaneo Nmap automatizado[/] contra uno o más objetivos y genera
    un reporte PDF con hallazgos, sugerencias de Metasploit y recomendaciones.
    """
    print_banner()

    # ── Validar que se proporcionó al menos un objetivo ────────────────────────
    if not target and not target_file:
        console.print(
            "[bold red]ERROR:[/] Debes especificar [cyan]--target[/] o [cyan]--file[/]."
        )
        raise typer.Exit(code=1)

    # ── Construir lista de targets ─────────────────────────────────────────────
    targets: list[str] = []

    if target:
        targets.append(target.strip())

    if target_file:
        raw_lines = target_file.read_text().splitlines()
        targets.extend(line.strip() for line in raw_lines if line.strip() and not line.startswith("#"))

    # Validar formato básico
    valid_targets = validate_targets(targets, console)
    if not valid_targets:
        raise typer.Exit(code=1)

    # Validar modo
    valid_modes = ("basic", "medium", "extreme")
    if mode not in valid_modes:
        console.print(f"[bold red]ERROR:[/] Modo inválido '{mode}'. Opciones: {', '.join(valid_modes)}")
        raise typer.Exit(code=1)

    # ── Validar proveedor y consentimiento para el envío a servicios externos ──
    provider = (ai_provider or "ollama").strip().lower()
    if ai_provider is not None:
        ai = True
    if provider not in AI_PROVIDER_LABELS:
        console.print(
            f"[bold red]ERROR:[/] Proveedor IA inválido '{provider}'. "
            f"Opciones: {', '.join(AI_PROVIDER_LABELS)}."
        )
        raise typer.Exit(code=1)
    if ai_model and not ai:
        console.print("[bold red]ERROR:[/] --ai-model requiere --ai o --ai-provider.")
        raise typer.Exit(code=1)
    if (allow_cloud_ai or share_target_identifiers) and not ai:
        console.print(
            "[bold red]ERROR:[/] Las opciones de consentimiento requieren --ai o --ai-provider."
        )
        raise typer.Exit(code=1)

    cloud_provider = provider != "ollama"
    ollama_url = os.environ.get("NMAP_OLLAMA_URL", "http://127.0.0.1:11434")
    remote_ollama = provider == "ollama" and not _is_local_ollama_endpoint(ollama_url)
    external_ai_endpoint = cloud_provider or remote_ollama
    if external_ai_endpoint and not allow_cloud_ai:
        console.print(
            "[bold red]ERROR:[/] El proveedor/endpoint seleccionado envía hallazgos a un servicio externo. "
            "Revisa el aviso y confirma explícitamente con --allow-cloud-ai."
        )
        raise typer.Exit(code=1)
    if not external_ai_endpoint and allow_cloud_ai:
        console.print(
            "[bold red]ERROR:[/] --allow-cloud-ai solo aplica a proveedores/endpoints externos."
        )
        raise typer.Exit(code=1)

    narrative_analyst = None
    if ai:
        try:
            # Validar claves/configuración antes de iniciar el escaneo.
            narrative_analyst = create_narrative_analyst(
                provider=provider,
                model=ai_model,
                share_target_identifiers=share_target_identifiers,
            )
        except RuntimeError as exc:
            console.print(f"[bold red]ERROR de configuración IA:[/] {exc}")
            raise typer.Exit(code=1)

    if external_ai_endpoint and ai:
        provider_label = AI_PROVIDER_LABELS[provider]
        if remote_ollama:
            provider_label += f" (endpoint remoto: {ollama_url})"
        identifier_notice = (
            "Se incluirán la IP y el hostname de cada hallazgo por autorización de "
            "--share-target-identifiers."
            if share_target_identifiers
            else "La IP y el hostname se omiten de la petición por defecto."
        )
        console.print(
            Panel(
                f"[bold]Proveedor:[/] {provider_label}\n"
                "Se enviarán al proveedor seleccionado los hallazgos técnicos necesarios "
                "para redactar el análisis (servicio, versión, evidencia y referencias).\n"
                f"{identifier_notice}\n"
                "La clave API se lee del entorno local y no se incluye en el reporte.",
                title="[bold yellow]Consentimiento de IA en la nube[/]",
                border_style="yellow",
            )
        )
    elif ai and share_target_identifiers:
        console.print(
            Panel(
                "Se incluirán IP y hostname en el prompt enviado a Ollama. "
                "Ollama usa el endpoint configurado en NMAP_OLLAMA_URL.",
                title="[bold yellow]Identificadores del objetivo habilitados[/]",
                border_style="yellow",
            )
        )

    # ── Confirmación interactiva ───────────────────────────────────────────────
    if not no_confirm:
        if not confirm_scan(targets, mode, ports, console):
            console.print("[yellow]Escaneo cancelado por el usuario.[/]")
            raise typer.Exit()

    # ── Ejecutar escaneo ───────────────────────────────────────────────────────
    scanner = NmapScanner(console=console)
    scan_results = scanner.run(targets=valid_targets, mode=mode, ports=ports)

    if not scan_results:
        console.print("[bold red]El escaneo no produjo resultados o falló.[/]")
        raise typer.Exit(code=1)

    # ── Cruzar con Metasploit ──────────────────────────────────────────────────
    mapper = MetasploitMapper()
    scan_results = mapper.enrich(scan_results)

    # ── Hallazgos con evidencia NVD / CISA ────────────────────────────────────
    security_findings = []
    ai_summary = ""
    if security_analysis or ai:
        analyst = SecurityAnalyst()
        with console.status("[bold cyan]Correlacionando resultados con NVD y CISA KEV…[/]"):
            security_findings = analyst.analyze(scan_results)
        for warning in analyst.warnings:
            console.print(f"[yellow]Aviso del analista:[/] {warning}")

        if security_findings:
            confirmed = sum(item.status == "confirmed" for item in security_findings)
            candidates = sum(item.status == "candidate" for item in security_findings)
            exposures = sum(item.status == "exposure" for item in security_findings)
            kev_count = sum(item.kev for item in security_findings)
            console.print(
                f"[bold]Analista:[/] {len(security_findings)} hallazgo(s): "
                f"[red]{confirmed} confirmado(s)[/], [yellow]{candidates} candidato(s)[/], "
                f"{exposures} exposición(es); [bold red]{kev_count} en CISA KEV[/]."
            )
        else:
            console.print("[green]Analista:[/] no encontró candidatos CVE ni exposiciones configuradas.")

        if ai:
            if security_findings:
                try:
                    provider_status = AI_PROVIDER_LABELS[provider]
                    if remote_ollama:
                        provider_status = "Ollama (endpoint remoto)"
                    with console.status(
                        f"[bold cyan]Generando narrativa con {provider_status}…[/]"
                    ):
                        ai_summary, narratives = narrative_analyst.generate(security_findings)
                    for finding in security_findings:
                        narrative = narratives.get(finding.finding_id)
                        if narrative:
                            if narrative.get("impact"):
                                finding.impact = narrative["impact"]
                            if narrative.get("remediation"):
                                finding.remediation = narrative["remediation"]
                            finding.ai_summary = narrative.get("summary", "")
                            finding.ai_confidence = narrative.get("confidence")
                            finding.ai_provider = provider_status
                            finding.ai_generated = True
                except RuntimeError as exc:
                    log_path = output.parent / "nmap_automator.log"
                    try:
                        log_exception_to_file(
                            log_path,
                            "Fallo durante la generación o validación de la narrativa IA.",
                        )
                        console.print(
                            f"[yellow]Narrativa IA omitida:[/] {exc}\n"
                            f"[yellow]Traceback completo:[/] {log_path}"
                        )
                    except OSError as log_error:
                        console.print(
                            f"[yellow]Narrativa IA omitida:[/] {exc}\n"
                            f"[red]No se pudo escribir el log {log_path}:[/] {log_error}"
                        )
            else:
                ai_summary = ""

    # ── Mostrar resumen en terminal ────────────────────────────────────────────
    print_summary_table(scan_results, console)

    # ── Generar reporte PDF ────────────────────────────────────────────────────
    output.parent.mkdir(parents=True, exist_ok=True)
    reporter = PDFReportGenerator(output_path=str(output), console=console)
    reporter.generate(
        scan_results,
        mode=mode,
        targets=valid_targets,
        findings=security_findings if security_analysis or ai else None,
        ai_summary=ai_summary,
    )

    console.print(
        Panel(
            f"[bold green]✔ Reporte generado:[/] [cyan]{output}[/]",
            title="[bold]Escaneo completado[/]",
            border_style="green",
        )
    )


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app()
