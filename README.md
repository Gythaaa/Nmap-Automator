# 🔍 NmapAutomator

> Herramienta de automatización de escaneo Nmap con interfaz Rich en terminal, sugerencias de módulos Metasploit y generación de reportes PDF profesionales.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## 📋 Características

| Característica | Detalle |
|---|---|
| 🖥️ Interfaz | Terminal con colores y barras de progreso (Rich + Typer) |
| 🎯 Entradas | IP, rango CIDR, rango con guión o archivo .txt |
| ⚡ Modos | Básico, Medio y Extremo |
| 🛡️ Metasploit | Base de datos integrada de módulos para ~20 servicios |
| 📄 Reporte | PDF profesional con hallazgos, vulns y recomendaciones |
| 🧹 Código | Modularizado, PEP 8, type hints, docstrings |

---

## 🏗️ Estructura del proyecto

```
nmap_automator/
├── main.py                    # Entry point CLI (Typer)
├── requirements.txt
├── README.md
│
├── core/
│   ├── __init__.py
│   ├── scanner.py             # Ejecución Nmap + parsing XML
│   └── metasploit_mapper.py   # Base de datos MSF + enriquecimiento
│
├── reports/
│   ├── __init__.py
│   └── pdf_report.py          # Generación de reporte PDF (ReportLab)
│
├── utils/
│   ├── __init__.py
│   ├── ui.py                  # Banner, tablas Rich, confirmación
│   └── validators.py          # Validación de IPs, CIDRs, hostnames
│
└── reports/                   # Carpeta de salida de reportes (auto-creada)
    └── reporte_nmap.pdf
```

---

## ⚙️ Instalación

### Prerrequisitos

- Python 3.10+
- Nmap instalado en el sistema

```bash
# Arch / CachyOS / Manjaro
sudo pacman -S nmap

# Debian / Ubuntu / Kali
sudo apt install nmap

# macOS
brew install nmap
```

### Clonar e instalar

```bash
git clone https://github.com/tu-usuario/nmap-automator.git
cd nmap-automator
pip install -r requirements.txt
```

---

## 🚀 Uso

### Escaneo básico de una IP

```bash
python main.py --target 192.168.1.1
```

### Escaneo medio de un rango CIDR

```bash
python main.py --target 192.168.1.0/24 --mode medium --ports 1-65535
```

### Escaneo extremo desde archivo de IPs

```bash
python main.py --file targets.txt --mode extreme --output /tmp/reporte_red.pdf
```

### Omitir confirmación (modo automatizado / scripts)

```bash
python main.py --target 10.10.10.5 --mode medium --yes
```

---

## 📊 Modos de escaneo

| Modo | Flags Nmap | Descripción |
|---|---|---|
| `basic` | `-F --open` | 100 puertos más comunes, rápido |
| `medium` | `-sV -sC -O --open` | Versiones, scripts y detección de OS |
| `extreme` | `-A -p- --script vuln --open` | Todos los puertos + NSE vuln (lento) |

---

## 🔌 Integración Metasploit

La herramienta cruza automáticamente los servicios detectados con una base de datos interna de más de **40 módulos Metasploit** clasificados por tipo (`auxiliary` / `exploit`), cubriendo servicios como:

- FTP, SSH, Telnet, SMTP
- HTTP/HTTPS, SMB, RDP
- MySQL, PostgreSQL, MSSQL, MongoDB, Redis
- SNMP, LDAP, VNC, DNS

Los módulos sugeridos se muestran en la terminal y se incluyen en el reporte PDF.

---

## 📄 Reporte PDF

El reporte generado incluye:

1. **Portada** con métricas de resumen
2. **Resumen ejecutivo** con tabla por host
3. **Sección por host** con puertos, servicios, scripts NSE y módulos MSF
4. **Recomendaciones** dinámicas según servicios encontrados
5. **Aviso legal**

---

## ⚠️ Aviso legal

Esta herramienta es para uso exclusivo en **entornos autorizados** y con fines de **auditoría de seguridad ética**. El uso no autorizado contra sistemas ajenos es ilegal. El autor no se responsabiliza por el mal uso de esta herramienta.

---

## 📜 Licencia

MIT License — ver [LICENSE](LICENSE) para detalles.

---

## 👤 Autor

**Gythaaa** — Cybersecurity Junior | eWPTX | eJPT

- Plataforma: KaliLinux - Windows
- Especialización: Web Application Penetration Testing
```
