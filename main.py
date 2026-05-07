#!/usr/bin/env python3
"""
NmapAutomator - Herramienta de automatización de escaneo Nmap con interfaz Rich
Autor: Mau | Cybersecurity Toolset
"""

import typer
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from core.scanner import NmapScanner
from core.metasploit_mapper import MetasploitMapper
from reports.pdf_report import PDFReportGenerator
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
        Path("reports/reporte_nmap.pdf"), "--output", "-o",
        help="Ruta del reporte PDF de salida.",
    ),
    no_confirm: bool = typer.Option(
        False, "--yes", "-y",
        help="Omitir confirmación antes de escanear.",
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

    # ── Mostrar resumen en terminal ────────────────────────────────────────────
    print_summary_table(scan_results, console)

    # ── Generar reporte PDF ────────────────────────────────────────────────────
    output.parent.mkdir(parents=True, exist_ok=True)
    reporter = PDFReportGenerator(output_path=str(output), console=console)
    reporter.generate(scan_results, mode=mode, targets=valid_targets)

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
