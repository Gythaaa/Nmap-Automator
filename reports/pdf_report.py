"""
reports/pdf_report.py
Genera un reporte profesional en PDF usando ReportLab con toda la información
del escaneo: hosts, puertos, servicios, vulnerabilidades y módulos Metasploit.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from rich.console import Console

from core.scanner import HostResult


# ── Paleta de colores ─────────────────────────────────────────────────────────
DARK_BG    = colors.HexColor("#0D1117")
ACCENT     = colors.HexColor("#58A6FF")
ACCENT2    = colors.HexColor("#3FB950")
RED        = colors.HexColor("#F85149")
ORANGE     = colors.HexColor("#E3B341")
LIGHT_GRAY = colors.HexColor("#C9D1D9")
MID_GRAY   = colors.HexColor("#30363D")
TABLE_HDR  = colors.HexColor("#161B22")
ROW_EVEN   = colors.HexColor("#0D1117")
ROW_ODD    = colors.HexColor("#161B22")


class PDFReportGenerator:
    """
    Genera un reporte PDF profesional con los resultados del escaneo.
    """

    def __init__(self, output_path: str, console: Optional[Console] = None):
        self.output_path = output_path
        self.console = console or Console()
        self._styles = self._build_styles()

    # ── API pública ───────────────────────────────────────────────────────────

    def generate(
        self,
        hosts: list[HostResult],
        mode: str,
        targets: list[str],
    ) -> None:
        """
        Construye y guarda el PDF con todos los hallazgos del escaneo.

        Args:
            hosts:   Lista de HostResult del scanner.
            mode:    Perfil usado (basic/medium/extreme).
            targets: Objetivos originales del escaneo.
        """
        self.console.print("[bold cyan]Generando reporte PDF…[/]")

        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2.5 * cm,
            bottomMargin=2 * cm,
            title="NmapAutomator — Reporte de Seguridad",
            author="NmapAutomator",
        )

        story = []
        story += self._build_cover(mode, targets, hosts)
        story.append(PageBreak())
        story += self._build_executive_summary(hosts, mode)
        story.append(PageBreak())

        for host in hosts:
            story += self._build_host_section(host)
            story.append(Spacer(1, 0.5 * cm))

        story += self._build_recommendations(hosts)
        story.append(PageBreak())
        story += self._build_footer_page()

        doc.build(story, onFirstPage=self._header_footer, onLaterPages=self._header_footer)
        self.console.print(f"[green]✔ PDF guardado en:[/] {self.output_path}")

    # ── Secciones del documento ───────────────────────────────────────────────

    def _build_cover(self, mode: str, targets: list[str], hosts: list[HostResult]) -> list:
        """Página de portada con título, fecha y resumen rápido."""
        s = self._styles
        now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        total_ports = sum(len(h.ports) for h in hosts)
        total_hosts_up = sum(1 for h in hosts if h.state == "up")

        cover = [
            Spacer(1, 3 * cm),
            Paragraph("REPORTE DE SEGURIDAD", s["cover_title"]),
            Paragraph("Análisis Automatizado de Red con Nmap", s["cover_sub"]),
            Spacer(1, 1 * cm),
            HRFlowable(width="100%", thickness=2, color=ACCENT),
            Spacer(1, 0.5 * cm),
            Paragraph(f"<b>Fecha:</b> {now}", s["cover_meta"]),
            Paragraph(f"<b>Modo de escaneo:</b> {mode.upper()}", s["cover_meta"]),
            Paragraph(f"<b>Objetivos:</b> {', '.join(targets)}", s["cover_meta"]),
            Spacer(1, 1 * cm),
        ]

        # Tabla de métricas rápidas
        metrics_data = [
            ["Hosts escaneados", "Hosts activos", "Puertos abiertos"],
            [str(len(hosts)), str(total_hosts_up), str(total_ports)],
        ]
        t = Table(metrics_data, colWidths=[5 * cm, 5 * cm, 5 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), TABLE_HDR),
            ("BACKGROUND", (0, 1), (-1, 1), MID_GRAY),
            ("TEXTCOLOR", (0, 0), (-1, 0), ACCENT),
            ("TEXTCOLOR", (0, 1), (-1, 1), LIGHT_GRAY),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("FONTSIZE", (0, 1), (-1, 1), 18),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [TABLE_HDR, MID_GRAY]),
            ("GRID", (0, 0), (-1, -1), 0.5, MID_GRAY),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        cover.append(t)
        cover.append(Spacer(1, 2 * cm))
        cover.append(Paragraph(
            "⚠ Este reporte es confidencial y fue generado con fines de pentesting autorizado.",
            s["warning"],
        ))
        return cover

    def _build_executive_summary(self, hosts: list[HostResult], mode: str) -> list:
        """Resumen ejecutivo con estadísticas generales."""
        s = self._styles
        story = [
            Paragraph("1. RESUMEN EJECUTIVO", s["section"]),
            HRFlowable(width="100%", thickness=1, color=ACCENT),
            Spacer(1, 0.3 * cm),
        ]

        total_ports = sum(len(h.ports) for h in hosts)
        hosts_with_vulns = sum(1 for h in hosts if h.vuln_scripts)
        hosts_with_msf = sum(
            1 for h in hosts if any(p.metasploit_modules for p in h.ports)
        )

        summary_text = (
            f"El escaneo en modo <b>{mode.upper()}</b> identificó <b>{len(hosts)}</b> host(s) "
            f"en la red objetivo. Se encontraron <b>{total_ports}</b> puertos abiertos en total. "
            f"<b>{hosts_with_vulns}</b> host(s) presentaron scripts de vulnerabilidad NSE positivos y "
            f"<b>{hosts_with_msf}</b> host(s) tienen servicios con módulos Metasploit aplicables."
        )
        story.append(Paragraph(summary_text, s["body"]))
        story.append(Spacer(1, 0.5 * cm))

        # Tabla resumen por host
        header = ["IP", "Hostname", "Estado", "Puertos abiertos", "OS detectado"]
        rows = [header]
        for h in hosts:
            rows.append([
                h.ip or "N/A",
                h.hostname or "N/A",
                h.state,
                str(len(h.ports)),
                (h.os_guess[:40] + "…") if len(h.os_guess) > 40 else h.os_guess,
            ])

        t = self._make_table(rows, col_widths=[3 * cm, 3.5 * cm, 2 * cm, 2.5 * cm, 5.5 * cm])
        story.append(t)
        return story

    def _build_host_section(self, host: HostResult) -> list:
        """Sección detallada por cada host: puertos, servicios y Metasploit."""
        s = self._styles
        label = f"{host.ip}" + (f" ({host.hostname})" if host.hostname else "")
        story = [
            Paragraph(f"HOST: {label}", s["host_title"]),
            Paragraph(f"<b>Sistema Operativo:</b> {host.os_guess}", s["body"]),
            Paragraph(f"<b>Estado:</b> {host.state}", s["body"]),
            Spacer(1, 0.3 * cm),
        ]

        if not host.ports:
            story.append(Paragraph("Sin puertos abiertos detectados.", s["body"]))
            return story

        # ── Tabla de puertos ───────────────────────────────────────────────────
        story.append(Paragraph("Puertos y Servicios", s["subsection"]))
        port_header = ["Puerto", "Protocolo", "Servicio", "Producto", "Versión"]
        port_rows = [port_header]
        for p in host.ports:
            port_rows.append([
                str(p.port),
                p.protocol,
                p.service or "—",
                p.product or "—",
                p.version or "—",
            ])

        t = self._make_table(
            port_rows,
            col_widths=[2 * cm, 2.5 * cm, 3 * cm, 4.5 * cm, 4.5 * cm],
        )
        story.append(t)
        story.append(Spacer(1, 0.3 * cm))

        # ── Scripts NSE de vulnerabilidades ───────────────────────────────────
        vuln_ports = [p for p in host.ports if p.scripts]
        if vuln_ports:
            story.append(Paragraph("Scripts NSE", s["subsection"]))
            for p in vuln_ports:
                for script_id, output in p.scripts.items():
                    snippet = output[:300].replace("\n", " ") + ("…" if len(output) > 300 else "")
                    story.append(Paragraph(
                        f"<b>[{p.port}/{p.protocol}] {script_id}:</b> {snippet}",
                        s["code"],
                    ))
            story.append(Spacer(1, 0.3 * cm))

        # Host-level vuln scripts
        if host.vuln_scripts:
            story.append(Paragraph("Scripts de vulnerabilidad (host)", s["subsection"]))
            for vs in host.vuln_scripts:
                snippet = vs["output"][:300].replace("\n", " ") + ("…" if len(vs["output"]) > 300 else "")
                story.append(Paragraph(
                    f"<b>{vs['id']}:</b> {snippet}", s["code"]
                ))
            story.append(Spacer(1, 0.3 * cm))

        # ── Sugerencias Metasploit ─────────────────────────────────────────────
        msf_ports = [p for p in host.ports if p.metasploit_modules]
        if msf_ports:
            story.append(Paragraph("Módulos Metasploit sugeridos", s["subsection"]))
            msf_header = ["Puerto", "Módulo", "Tipo", "Descripción"]
            msf_rows = [msf_header]
            for p in msf_ports:
                for mod in p.metasploit_modules:
                    msf_rows.append([
                        str(p.port),
                        mod.get("module", ""),
                        mod.get("type", ""),
                        mod.get("description", ""),
                    ])

            t = self._make_table(
                msf_rows,
                col_widths=[1.5 * cm, 5.5 * cm, 2 * cm, 7.5 * cm],
                highlight_col=1,
                highlight_color=ACCENT,
            )
            story.append(t)

        story.append(HRFlowable(width="100%", thickness=0.5, color=MID_GRAY))
        return story

    def _build_recommendations(self, hosts: list[HostResult]) -> list:
        """Sección de recomendaciones generales basadas en lo encontrado."""
        s = self._styles
        story = [
            Paragraph("2. RECOMENDACIONES", s["section"]),
            HRFlowable(width="100%", thickness=1, color=ACCENT),
            Spacer(1, 0.3 * cm),
        ]

        recs = self._derive_recommendations(hosts)
        for i, rec in enumerate(recs, 1):
            story.append(Paragraph(f"{i}. {rec}", s["body"]))
            story.append(Spacer(1, 0.2 * cm))

        return story

    def _build_footer_page(self) -> list:
        """Página final con aviso legal."""
        s = self._styles
        return [
            Paragraph("AVISO LEGAL", s["section"]),
            HRFlowable(width="100%", thickness=1, color=ACCENT),
            Spacer(1, 0.5 * cm),
            Paragraph(
                "Este reporte fue generado automáticamente por NmapAutomator con fines "
                "de auditoría de seguridad autorizada. El uso de esta información para "
                "actividades no autorizadas es ilegal y éticamente inaceptable. "
                "El autor no se responsabiliza por el mal uso de estos datos.",
                s["body"],
            ),
        ]

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _derive_recommendations(self, hosts: list[HostResult]) -> list[str]:
        """Genera recomendaciones dinámicas según los servicios encontrados."""
        recs: list[str] = []
        services_found: set[str] = set()

        for host in hosts:
            for p in host.ports:
                services_found.add(p.service.lower())

        if "ftp" in services_found:
            recs.append("Deshabilitar FTP y migrar a SFTP/FTPS. Verificar acceso anónimo.")
        if "telnet" in services_found:
            recs.append("Eliminar Telnet y reemplazar por SSH con autenticación por llave.")
        if "ssh" in services_found:
            recs.append("Asegurar SSH: deshabilitar root login, usar solo claves públicas, cambiar el puerto por defecto.")
        if "http" in services_found:
            recs.append("Implementar HTTPS con TLS 1.2+ y redirigir todo el tráfico HTTP.")
        if "snmp" in services_found:
            recs.append("Cambiar community strings por defecto de SNMP y migrar a SNMPv3.")
        if "microsoft-ds" in services_found or "netbios-ssn" in services_found:
            recs.append("Aplicar parches de seguridad para SMB (MS17-010). Deshabilitar SMBv1.")
        if "ms-wbt-server" in services_found:
            recs.append("Restringir RDP con VPN o IP allowlisting. Aplicar parche BlueKeep.")
        if "mysql" in services_found or "postgresql" in services_found:
            recs.append("Bases de datos no deben ser accesibles desde la red pública. Usar firewall.")
        if "redis" in services_found:
            recs.append("Configurar autenticación en Redis y vincularlo solo a localhost.")

        if not recs:
            recs.append("No se detectaron servicios de alto riesgo obvios. Mantener parches y políticas de acceso.")

        recs.append("Revisar todos los servicios expuestos y aplicar el principio de mínimo privilegio.")
        recs.append("Implementar un sistema de detección de intrusos (IDS/IPS) en la red.")
        recs.append("Realizar auditorías de seguridad de forma periódica.")
        return recs

    def _make_table(
        self,
        rows: list[list[str]],
        col_widths: list[float],
        highlight_col: Optional[int] = None,
        highlight_color: colors.Color = ACCENT,
    ) -> Table:
        """Construye una tabla estilizada con cabecera oscura y filas alternadas."""
        s = self._styles

        # Convertir celdas a Paragraphs para wrapping automático
        styled_rows = []
        for i, row in enumerate(rows):
            styled_row = []
            for j, cell in enumerate(row):
                style = s["table_header"] if i == 0 else (
                    s["table_cell_accent"] if (highlight_col is not None and j == highlight_col) else s["table_cell"]
                )
                styled_row.append(Paragraph(str(cell), style))
            styled_rows.append(styled_row)

        t = Table(styled_rows, colWidths=col_widths, repeatRows=1)
        row_count = len(rows)

        ts = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), TABLE_HDR),
            ("TEXTCOLOR", (0, 0), (-1, 0), ACCENT),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.25, MID_GRAY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])

        # Filas alternadas
        for r in range(1, row_count):
            bg = ROW_EVEN if r % 2 == 0 else ROW_ODD
            ts.add("BACKGROUND", (0, r), (-1, r), bg)

        t.setStyle(ts)
        return t

    def _header_footer(self, canvas, doc):
        """Agrega encabezado y pie de página en cada hoja."""
        canvas.saveState()
        w, h = A4
        # Header line
        canvas.setStrokeColor(ACCENT)
        canvas.setLineWidth(1.5)
        canvas.line(2 * cm, h - 1.5 * cm, w - 2 * cm, h - 1.5 * cm)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(ACCENT)
        canvas.drawString(2 * cm, h - 1.2 * cm, "NmapAutomator — Reporte de Seguridad")
        canvas.setFillColor(LIGHT_GRAY)
        canvas.drawRightString(w - 2 * cm, h - 1.2 * cm, datetime.now().strftime("%d/%m/%Y"))
        # Footer
        canvas.setStrokeColor(MID_GRAY)
        canvas.setLineWidth(0.5)
        canvas.line(2 * cm, 1.2 * cm, w - 2 * cm, 1.2 * cm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(LIGHT_GRAY)
        canvas.drawCentredString(w / 2, 0.8 * cm, f"Página {doc.page} — Confidencial")
        canvas.restoreState()

    def _build_styles(self) -> dict:
        """Define todos los estilos tipográficos del documento."""
        base = getSampleStyleSheet()

        def ps(name, **kw) -> ParagraphStyle:
            return ParagraphStyle(name, **kw)

        return {
            "cover_title": ps(
                "cover_title",
                fontSize=28, textColor=ACCENT, alignment=TA_CENTER,
                fontName="Helvetica-Bold", spaceAfter=8,
            ),
            "cover_sub": ps(
                "cover_sub",
                fontSize=14, textColor=LIGHT_GRAY, alignment=TA_CENTER,
                fontName="Helvetica", spaceAfter=20,
            ),
            "cover_meta": ps(
                "cover_meta",
                fontSize=11, textColor=LIGHT_GRAY, fontName="Helvetica",
                spaceAfter=4,
            ),
            "section": ps(
                "section",
                fontSize=14, textColor=ACCENT, fontName="Helvetica-Bold",
                spaceAfter=6, spaceBefore=12,
            ),
            "host_title": ps(
                "host_title",
                fontSize=12, textColor=ACCENT2, fontName="Helvetica-Bold",
                spaceAfter=4, spaceBefore=12,
            ),
            "subsection": ps(
                "subsection",
                fontSize=10, textColor=ORANGE, fontName="Helvetica-Bold",
                spaceAfter=4, spaceBefore=8,
            ),
            "body": ps(
                "body",
                fontSize=9, textColor=LIGHT_GRAY, fontName="Helvetica",
                spaceAfter=4, leading=14,
            ),
            "code": ps(
                "code",
                fontSize=7.5, textColor=LIGHT_GRAY, fontName="Courier",
                spaceAfter=3, leading=12, backColor=MID_GRAY,
                leftIndent=8, rightIndent=8,
            ),
            "warning": ps(
                "warning",
                fontSize=9, textColor=ORANGE, fontName="Helvetica-Bold",
                alignment=TA_CENTER, spaceAfter=4,
            ),
            "table_header": ps(
                "table_header",
                fontSize=8, textColor=ACCENT, fontName="Helvetica-Bold",
            ),
            "table_cell": ps(
                "table_cell",
                fontSize=7.5, textColor=LIGHT_GRAY, fontName="Helvetica",
            ),
            "table_cell_accent": ps(
                "table_cell_accent",
                fontSize=7.5, textColor=ACCENT2, fontName="Courier",
            ),
        }
