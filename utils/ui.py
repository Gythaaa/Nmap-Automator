"""
utils/ui.py
Componentes de interfaz de terminal: banner, tablas de resumen, confirmación.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns

from core.scanner import HostResult


# ── Banner ASCII ──────────────────────────────────────────────────────────────

BANNER = r"""
 ███╗   ██╗███╗   ███╗ █████╗ ██████╗      █████╗ ██╗   ██╗████████╗ ██████╗
 ████╗  ██║████╗ ████║██╔══██╗██╔══██╗    ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗
 ██╔██╗ ██║██╔████╔██║███████║██████╔╝    ███████║██║   ██║   ██║   ██║   ██║
 ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝     ██╔══██║██║   ██║   ██║   ██║   ██║
 ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║         ██║  ██║╚██████╔╝   ██║   ╚██████╔╝
 ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝         ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝
"""


def print_banner(console: Console = None) -> None:
    """Imprime el banner de bienvenida con información de versión."""
    c = console or Console()
    c.print(f"[bold cyan]{BANNER}[/]")
    c.print(
        Panel(
            "[bold white]Herramienta de Automatización Nmap[/] · "
            "[dim]v1.0.0[/] · "
            "[cyan]by Mau[/] · "
            "[dim]Solo para uso ético y autorizado[/]",
            style="bold cyan",
            border_style="dim cyan",
            expand=False,
        )
    )
    c.print()


def confirm_scan(
    targets: list[str],
    mode: str,
    ports: str,
    console: Console,
) -> bool:
    """
    Muestra un resumen del escaneo pendiente y pide confirmación al usuario.

    Returns:
        True si el usuario confirma, False si cancela.
    """
    mode_colors = {"basic": "green", "medium": "yellow", "extreme": "bold red"}
    mode_color = mode_colors.get(mode, "white")

    console.print(
        Panel(
            f"[bold]Modo:[/]    [{mode_color}]{mode.upper()}[/]\n"
            f"[bold]Targets:[/] {', '.join(targets)}\n"
            f"[bold]Puertos:[/] {'todos (-p-)' if mode == 'extreme' else ports}",
            title="[yellow]⚠  Confirmar escaneo[/]",
            border_style="yellow",
        )
    )

    if mode == "extreme":
        console.print(
            "[bold red]ADVERTENCIA:[/] El modo EXTREMO puede tardar horas y "
            "generar mucho tráfico de red. Asegúrate de tener autorización.\n"
        )

    answer = console.input("[bold yellow]¿Continuar? \\[s/N] [/]").strip().lower()
    return answer in ("s", "si", "sí", "y", "yes")


def print_summary_table(hosts: list[HostResult], console: Console) -> None:
    """
    Imprime una tabla Rich con el resumen de resultados en la terminal.
    """
    console.print()
    console.rule("[bold cyan]RESULTADOS DEL ESCANEO[/]")
    console.print()

    for host in hosts:
        label = f"[bold cyan]{host.ip}[/]"
        if host.hostname:
            label += f" [dim]({host.hostname})[/]"

        # Tabla de puertos para este host
        table = Table(
            title=label,
            show_header=True,
            header_style="bold magenta",
            border_style="dim",
            show_lines=True,
            expand=False,
        )
        table.add_column("Puerto", style="bold white", width=8)
        table.add_column("Proto", width=6)
        table.add_column("Servicio", style="cyan", width=14)
        table.add_column("Producto", width=18)
        table.add_column("Versión", width=14)
        table.add_column("MSF Sugeridos", style="green", width=12)
        table.add_column("NSE Scripts", style="yellow", width=10)

        for p in host.ports:
            state_style = "green" if p.state == "open" else "red"
            table.add_row(
                f"[{state_style}]{p.port}[/]",
                p.protocol,
                p.service or "—",
                p.product or "—",
                p.version or "—",
                str(len(p.metasploit_modules)),
                str(len(p.scripts)),
            )

        if not host.ports:
            table.add_row("—", "—", "Sin puertos abiertos", "—", "—", "—", "—")

        console.print(table)

        # Mostrar módulos MSF si los hay
        msf_ports = [p for p in host.ports if p.metasploit_modules]
        if msf_ports:
            msf_table = Table(
                title=f"[bold green]Módulos Metasploit — {host.ip}[/]",
                show_header=True,
                header_style="bold green",
                border_style="dim green",
                show_lines=False,
                expand=False,
            )
            msf_table.add_column("Puerto", width=8)
            msf_table.add_column("Módulo", style="bold cyan", width=50)
            msf_table.add_column("Tipo", width=10)
            msf_table.add_column("Descripción", width=45)

            for p in msf_ports:
                for mod in p.metasploit_modules:
                    msf_table.add_row(
                        str(p.port),
                        mod.get("module", ""),
                        f"[{'red' if mod.get('type') == 'exploit' else 'yellow'}]{mod.get('type', '')}[/]",
                        mod.get("description", ""),
                    )

            console.print(msf_table)

        console.print()
