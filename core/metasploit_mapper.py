"""
core/metasploit_mapper.py
Cruza servicios detectados con una base de datos de módulos Metasploit conocidos
y sugiere exploits relevantes para cada puerto/servicio abierto.
"""

from core.scanner import HostResult, PortInfo


# ── Base de datos de sugerencias ──────────────────────────────────────────────
# Formato: clave = (servicio, puerto_o_None)
# Valor   = lista de módulos/aux Metasploit con descripción breve.

MSF_DATABASE: dict[tuple[str, int | None], list[dict]] = {

    # ── FTP ───────────────────────────────────────────────────────────────────
    ("ftp", 21): [
        {"module": "auxiliary/scanner/ftp/anonymous", "type": "auxiliary",
         "description": "Detecta acceso FTP anónimo"},
        {"module": "auxiliary/scanner/ftp/ftp_version", "type": "auxiliary",
         "description": "Banner grabbing FTP"},
        {"module": "exploit/unix/ftp/vsftpd_234_backdoor", "type": "exploit",
         "description": "Backdoor en vsftpd 2.3.4 (CVE-2011-2523)"},
        {"module": "exploit/multi/handler", "type": "exploit",
         "description": "Manejador genérico para shells reversas"},
    ],

    # ── SSH ───────────────────────────────────────────────────────────────────
    ("ssh", 22): [
        {"module": "auxiliary/scanner/ssh/ssh_version", "type": "auxiliary",
         "description": "Versión e información del banner SSH"},
        {"module": "auxiliary/scanner/ssh/ssh_login", "type": "auxiliary",
         "description": "Brute-force de credenciales SSH"},
        {"module": "auxiliary/scanner/ssh/ssh_enumusers", "type": "auxiliary",
         "description": "Enumeración de usuarios vía timing (CVE-2018-15473)"},
    ],

    # ── Telnet ────────────────────────────────────────────────────────────────
    ("telnet", 23): [
        {"module": "auxiliary/scanner/telnet/telnet_version", "type": "auxiliary",
         "description": "Banner grabbing Telnet"},
        {"module": "auxiliary/scanner/telnet/bsdi_telnet_login", "type": "auxiliary",
         "description": "Login brute-force Telnet"},
    ],

    # ── SMTP ──────────────────────────────────────────────────────────────────
    ("smtp", 25): [
        {"module": "auxiliary/scanner/smtp/smtp_version", "type": "auxiliary",
         "description": "Versión del servidor SMTP"},
        {"module": "auxiliary/scanner/smtp/smtp_enum", "type": "auxiliary",
         "description": "Enumeración de usuarios SMTP (VRFY/EXPN)"},
    ],

    # ── DNS ───────────────────────────────────────────────────────────────────
    ("domain", 53): [
        {"module": "auxiliary/gather/dns_info", "type": "auxiliary",
         "description": "Recopilación de información DNS"},
        {"module": "auxiliary/scanner/dns/dns_amp", "type": "auxiliary",
         "description": "Verificación de amplificación DNS"},
    ],

    # ── HTTP ──────────────────────────────────────────────────────────────────
    ("http", 80): [
        {"module": "auxiliary/scanner/http/http_version", "type": "auxiliary",
         "description": "Versión del servidor HTTP"},
        {"module": "auxiliary/scanner/http/dir_scanner", "type": "auxiliary",
         "description": "Escaneo de directorios y ficheros"},
        {"module": "auxiliary/scanner/http/robots_txt", "type": "auxiliary",
         "description": "Analiza robots.txt en busca de rutas ocultas"},
        {"module": "exploit/multi/http/struts2_content_type_ognl", "type": "exploit",
         "description": "Apache Struts2 RCE (CVE-2017-5638)"},
    ],

    # ── POP3 ─────────────────────────────────────────────────────────────────
    ("pop3", 110): [
        {"module": "auxiliary/scanner/pop3/pop3_version", "type": "auxiliary",
         "description": "Banner grabbing POP3"},
        {"module": "auxiliary/scanner/pop3/pop3_login", "type": "auxiliary",
         "description": "Brute-force POP3"},
    ],

    # ── NetBIOS / SMB ─────────────────────────────────────────────────────────
    ("netbios-ssn", 139): [
        {"module": "auxiliary/scanner/smb/smb_version", "type": "auxiliary",
         "description": "Versión SMB y hostname NetBIOS"},
        {"module": "exploit/windows/smb/ms17_010_eternalblue", "type": "exploit",
         "description": "EternalBlue SMBv1 (CVE-2017-0144) — WannaCry"},
    ],

    ("microsoft-ds", 445): [
        {"module": "auxiliary/scanner/smb/smb_ms17_010", "type": "auxiliary",
         "description": "Detección de MS17-010 (EternalBlue)"},
        {"module": "exploit/windows/smb/ms17_010_eternalblue", "type": "exploit",
         "description": "EternalBlue SMBv1 RCE (CVE-2017-0144)"},
        {"module": "exploit/windows/smb/ms17_010_psexec", "type": "exploit",
         "description": "EternalBlue + PSExec"},
        {"module": "auxiliary/scanner/smb/smb_enumshares", "type": "auxiliary",
         "description": "Enumeración de shares SMB"},
        {"module": "auxiliary/scanner/smb/smb_enumusers", "type": "auxiliary",
         "description": "Enumeración de usuarios SMB"},
    ],

    # ── IMAP ─────────────────────────────────────────────────────────────────
    ("imap", 143): [
        {"module": "auxiliary/scanner/imap/imap_version", "type": "auxiliary",
         "description": "Banner grabbing IMAP"},
    ],

    # ── SNMP ─────────────────────────────────────────────────────────────────
    ("snmp", 161): [
        {"module": "auxiliary/scanner/snmp/snmp_enum", "type": "auxiliary",
         "description": "Enumeración SNMP (community strings)"},
        {"module": "auxiliary/scanner/snmp/snmp_login", "type": "auxiliary",
         "description": "Brute-force community strings SNMP"},
    ],

    # ── LDAP ─────────────────────────────────────────────────────────────────
    ("ldap", 389): [
        {"module": "auxiliary/gather/ldap_query", "type": "auxiliary",
         "description": "Consultas LDAP para enumeración de AD"},
        {"module": "auxiliary/scanner/ldap/ldap_login", "type": "auxiliary",
         "description": "Brute-force LDAP"},
    ],

    # ── HTTPS ─────────────────────────────────────────────────────────────────
    ("https", 443): [
        {"module": "auxiliary/scanner/http/ssl_version", "type": "auxiliary",
         "description": "Versión SSL/TLS y cifrados"},
        {"module": "auxiliary/scanner/http/http_version", "type": "auxiliary",
         "description": "Versión del servidor HTTPS"},
        {"module": "auxiliary/scanner/http/heartbleed", "type": "auxiliary",
         "description": "Detección Heartbleed (CVE-2014-0160)"},
    ],

    # ── MSSQL ────────────────────────────────────────────────────────────────
    ("ms-sql-s", 1433): [
        {"module": "auxiliary/scanner/mssql/mssql_ping", "type": "auxiliary",
         "description": "Detección de instancias MSSQL"},
        {"module": "auxiliary/scanner/mssql/mssql_login", "type": "auxiliary",
         "description": "Brute-force MSSQL"},
        {"module": "auxiliary/admin/mssql/mssql_exec", "type": "auxiliary",
         "description": "Ejecución de comandos vía xp_cmdshell"},
    ],

    # ── MySQL ─────────────────────────────────────────────────────────────────
    ("mysql", 3306): [
        {"module": "auxiliary/scanner/mysql/mysql_version", "type": "auxiliary",
         "description": "Versión del servidor MySQL"},
        {"module": "auxiliary/scanner/mysql/mysql_login", "type": "auxiliary",
         "description": "Brute-force MySQL"},
        {"module": "auxiliary/admin/mysql/mysql_enum", "type": "auxiliary",
         "description": "Enumeración de usuarios MySQL"},
    ],

    # ── RDP ───────────────────────────────────────────────────────────────────
    ("ms-wbt-server", 3389): [
        {"module": "auxiliary/scanner/rdp/rdp_scanner", "type": "auxiliary",
         "description": "Escaneo y versión RDP"},
        {"module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce", "type": "exploit",
         "description": "BlueKeep RCE pre-auth (CVE-2019-0708)"},
        {"module": "auxiliary/scanner/rdp/cve_2019_0708_bluekeep", "type": "auxiliary",
         "description": "Detección BlueKeep"},
    ],

    # ── PostgreSQL ────────────────────────────────────────────────────────────
    ("postgresql", 5432): [
        {"module": "auxiliary/scanner/postgres/postgres_version", "type": "auxiliary",
         "description": "Versión PostgreSQL"},
        {"module": "auxiliary/scanner/postgres/postgres_login", "type": "auxiliary",
         "description": "Brute-force PostgreSQL"},
    ],

    # ── VNC ───────────────────────────────────────────────────────────────────
    ("vnc", 5900): [
        {"module": "auxiliary/scanner/vnc/vnc_none_auth", "type": "auxiliary",
         "description": "Detecta VNC sin autenticación"},
        {"module": "auxiliary/scanner/vnc/vnc_login", "type": "auxiliary",
         "description": "Brute-force VNC"},
    ],

    # ── Redis ─────────────────────────────────────────────────────────────────
    ("redis", 6379): [
        {"module": "auxiliary/scanner/redis/redis_login", "type": "auxiliary",
         "description": "Detección de Redis sin autenticación"},
        {"module": "exploit/linux/redis/redis_replication_cmd_exec", "type": "exploit",
         "description": "RCE vía replicación Redis (sin auth)"},
    ],

    # ── MongoDB ───────────────────────────────────────────────────────────────
    ("mongod", 27017): [
        {"module": "auxiliary/scanner/mongodb/mongodb_login", "type": "auxiliary",
         "description": "Detección y brute-force MongoDB"},
    ],
}

# Mapeo de servicios genéricos por nombre (sin importar el puerto)
SERVICE_NAME_MAP: dict[str, list[dict]] = {
    "http": MSF_DATABASE.get(("http", 80), []),
    "https": MSF_DATABASE.get(("https", 443), []),
    "ftp": MSF_DATABASE.get(("ftp", 21), []),
    "ssh": MSF_DATABASE.get(("ssh", 22), []),
    "telnet": MSF_DATABASE.get(("telnet", 23), []),
    "smtp": MSF_DATABASE.get(("smtp", 25), []),
    "mysql": MSF_DATABASE.get(("mysql", 3306), []),
    "redis": MSF_DATABASE.get(("redis", 6379), []),
}


# ── Clase principal ───────────────────────────────────────────────────────────

class MetasploitMapper:
    """
    Enriquece los resultados del escaneo con sugerencias de módulos Metasploit.
    """

    def enrich(self, hosts: list[HostResult]) -> list[HostResult]:
        """
        Recorre todos los puertos abiertos de cada host y asigna módulos MSF.

        Args:
            hosts: Lista de HostResult ya populada por NmapScanner.

        Returns:
            La misma lista con el campo `metasploit_modules` de cada PortInfo populado.
        """
        for host in hosts:
            for port_info in host.ports:
                modules = self._lookup(port_info)
                port_info.metasploit_modules = modules

        return hosts

    # ── Helpers privados ──────────────────────────────────────────────────────

    def _lookup(self, port_info: PortInfo) -> list[dict]:
        """
        Busca módulos Metasploit para un PortInfo dado, usando:
        1. Clave exacta (servicio, puerto)
        2. Clave por nombre de servicio
        3. Clave por puerto genérico
        """
        # 1. Coincidencia exacta servicio + puerto
        key = (port_info.service.lower(), port_info.port)
        if key in MSF_DATABASE:
            return MSF_DATABASE[key]

        # 2. Por nombre de servicio sin importar puerto
        svc = port_info.service.lower()
        if svc in SERVICE_NAME_MAP:
            return SERVICE_NAME_MAP[svc]

        # 3. Buscar por puerto únicamente
        for (db_svc, db_port), modules in MSF_DATABASE.items():
            if db_port == port_info.port:
                return modules

        return []
