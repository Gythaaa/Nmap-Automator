"""
core/scanner.py
Módulo principal de escaneo. Abstrae la ejecución de Nmap y parsea resultados.
"""

import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel


# ── Estructuras de datos ──────────────────────────────────────────────────────

@dataclass
class PortInfo:
    """Representa un puerto individual con su información de servicio."""
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    extra_info: str
    scripts: dict[str, str] = field(default_factory=dict)
    metasploit_modules: list[dict] = field(default_factory=list) # Cambiado a dict para coincidir con el mapper


@dataclass
class HostResult:
    """Resultado completo de un host escaneado."""
    ip: str
    hostname: str
    state: str
    os_guess: str
    ports: list[PortInfo] = field(default_factory=list)
    vuln_scripts: list[dict] = field(default_factory=list)


# ── Perfiles de escaneo ───────────────────────────────────────────────────────

SCAN_PROFILES: dict[str, dict] = {
    "basic": {
        "label": "Básico — 100 puertos principales",
        "flags": ["-F", "--open", "-T4"], # Reincluido -F para velocidad real
        "color": "green",
    },
    "medium": {
        "label": "Medio — Servicios, versiones y OS",
        "flags": ["-sV", "-sC", "-O", "--open", "-T4"],
        "color": "yellow",
    },
    "extreme": {
        "label": "Extremo — Todos los puertos + NSE vuln",
        "flags": ["-A", "-p-", "--script", "vuln", "--open", "-T4"],
        "color": "red",
    },
}


# ── Clase principal ───────────────────────────────────────────────────────────

class NmapScanner:
    """
    Wrapper sobre Nmap que ejecuta escaneos y parsea la salida XML.
    """

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def run(
        self,
        targets: list[str],
        mode: str = "basic",
        ports: str = "1-1000",
    ) -> list[HostResult]:
        profile = SCAN_PROFILES[mode]
        self.console.print(
            Panel(
                f"[bold]Modo:[/] [{profile['color']}]{profile['label']}[/]\n"
                f"[bold]Objetivos:[/] {', '.join(targets)}\n"
                f"[bold]Puertos:[/] {'todos (-p-)' if mode == 'extreme' else ports}",
                title="[bold cyan]⚡ Iniciando escaneo Nmap[/]",
                border_style="cyan",
            )
        )

        cmd = self._build_command(targets, profile["flags"], ports, mode)
        self.console.print(f"[dim]Comando: {' '.join(cmd)}[/]\n")

        xml_output = self._execute(cmd, profile["color"])

        if not xml_output:
            return []

        return self._parse_xml(xml_output)

    def _build_command(self, targets: list[str], flags: list[str], ports: str, mode: str) -> list[str]:
        cmd = ["nmap", "-oX", "-", "-Pn"]
        cmd.extend(flags)
        if mode != "extreme" and ports and ports != "default":
            # Si el modo es básico y tiene -F, nmap ignorará el -p 1-1000. 
            # Es mejor dejar que el flag profile mande.
            if "-F" not in flags:
                cmd.extend(["-p", ports])
        cmd.extend(targets)
        return cmd

    def _execute(self, cmd: list[str], color: str) -> str:
        xml_data = ""
        with Progress(
            SpinnerColumn(style=f"bold {color}"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40, style=color),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        ) as progress:
            task = progress.add_task("[bold]Escaneando…[/]", total=None)
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
                xml_data = result.stdout
                if result.returncode != 0 and not xml_data:
                    self.console.print(f"[bold red]Nmap error:[/] {result.stderr.strip()}")
                    return ""
            except Exception as e:
                self.console.print(f"[bold red]Error de ejecución:[/] {e}")
                return ""
            progress.update(task, completed=True)
        return xml_data

    def _parse_xml(self, xml_data: str) -> list[HostResult]:
        results: list[HostResult] = []
        try:
            root = ET.fromstring(xml_data)
        except ET.ParseError as e:
            self.console.print(f"[bold red]Error parseando XML:[/] {e}")
            return []

        for host_elem in root.findall("host"):
            # ── Estado del host ────────────────────────────────────────────────
            status_elem = host_elem.find("status")
            host_state = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

            # ── IP y hostname ──────────────────────────────────────────────────
            ip = ""
            hostname = ""
            for addr in host_elem.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr", "")

            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                hn = hostnames_elem.find("hostname")
                if hn is not None:
                    hostname = hn.get("name", "")

            # ── Sistema operativo ──────────────────────────────────────────────
            os_guess = "Desconocido / Protegido"
            os_elem = host_elem.find("os")
            if os_elem is not None:
                os_matches = os_elem.findall("osmatch")
                if os_matches:
                    best_match = os_matches[0]
                    os_name = best_match.get("name", "N/A")
                    os_acc = best_match.get("accuracy", "0")
                    os_guess = f"{os_name} ({os_acc}% precisión)"

            # Creación del objeto HostResult
            host_result = HostResult(
                ip=ip,
                hostname=hostname,
                state=host_state,
                os_guess=os_guess,
            )

            # ── Puertos ────────────────────────────────────────────────────────
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port_id = int(port_elem.get("portid", 0))
                    protocol = port_elem.get("protocol", "tcp")
                    state_elem = port_elem.find("state")
                    port_state = state_elem.get("state", "") if state_elem is not None else ""

                    if port_state != "open":
                        continue

                    service_elem = port_elem.find("service")
                    service = product = version = extra = ""
                    if service_elem is not None:
                        service = service_elem.get("name", "")
                        product = service_elem.get("product", "")
                        version = service_elem.get("version", "")
                        extra = service_elem.get("extrainfo", "")

                    scripts: dict[str, str] = {}
                    for script_elem in port_elem.findall("script"):
                        scripts[script_elem.get("id", "")] = script_elem.get("output", "")

                    port_info = PortInfo(
                        port=port_id,
                        protocol=protocol,
                        state=port_state,
                        service=service,
                        product=product,
                        version=version,
                        extra_info=extra,
                        scripts=scripts,
                    )
                    host_result.ports.append(port_info)

            # ── Scripts de host (vuln, etc.) ───────────────────────────────────
            hostscript_elem = host_elem.find("hostscript")
            if hostscript_elem is not None:
                for script_elem in hostscript_elem.findall("script"):
                    script_id = script_elem.get("id", "")
                    script_output = script_elem.get("output", "")
                    if script_output:
                        host_result.vuln_scripts.append({
                            "id": script_id,
                            "output": script_output,
                        })

            results.append(host_result)

        return results