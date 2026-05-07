"""
utils/validators.py
Funciones de validación de targets (IPs, rangos CIDR, hostnames).
"""

import re
import ipaddress
from rich.console import Console


# ── Patrones ──────────────────────────────────────────────────────────────────

# Hostname RFC 1123 simplificado
HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def validate_targets(targets: list[str], console: Console) -> list[str]:
    """
    Valida cada target y retorna solo los que tienen formato correcto.

    Acepta:
      - IPv4 individual (192.168.1.1)
      - Rango CIDR (192.168.1.0/24)
      - Rango con guión (192.168.1.1-10)
      - Hostname (example.com)

    Args:
        targets: Lista de strings a validar.
        console: Instancia Rich para mostrar errores.

    Returns:
        Lista de targets válidos.
    """
    valid: list[str] = []

    for t in targets:
        if _is_valid_ipv4(t):
            valid.append(t)
        elif _is_valid_cidr(t):
            valid.append(t)
        elif _is_valid_ip_range(t):
            valid.append(t)
        elif _is_valid_hostname(t):
            valid.append(t)
        else:
            console.print(f"[bold yellow]ADVERTENCIA:[/] Target inválido ignorado: [red]{t}[/]")

    if not valid:
        console.print("[bold red]ERROR:[/] No hay targets válidos para escanear.")

    return valid


# ── Helpers privados ──────────────────────────────────────────────────────────

def _is_valid_ipv4(value: str) -> bool:
    """Valida una IP IPv4 individual."""
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _is_valid_cidr(value: str) -> bool:
    """Valida un rango CIDR (ej: 192.168.1.0/24)."""
    try:
        ipaddress.IPv4Network(value, strict=False)
        return "/" in value
    except ValueError:
        return False


def _is_valid_ip_range(value: str) -> bool:
    """Valida rango tipo 192.168.1.1-50 (Nmap acepta este formato)."""
    # Formato: A.B.C.D-E donde E es un número del último octeto
    parts = value.rsplit("-", 1)
    if len(parts) != 2:
        return False
    base, end = parts
    if not _is_valid_ipv4(base):
        return False
    try:
        end_int = int(end)
        return 0 <= end_int <= 255
    except ValueError:
        return False


def _is_valid_hostname(value: str) -> bool:
    """Valida un hostname básico."""
    return bool(HOSTNAME_RE.match(value))
