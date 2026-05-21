#!/usr/bin/env python3
"""
=============================================================================
monitor_honeylab.py — Monitor de Honeytokens & Defensa Activa
Laboratorio Blue Team | Auditoría PostgreSQL
=============================================================================
Funciones:
  1. Parsea el log de PostgreSQL en tiempo real buscando accesos a
     la tabla honeytoken tb_credenciales_vpn_admin
  2. Muestra alertas formateadas en consola con colores
  3. Guarda incidentes en incidents.jsonl para análisis posterior
=============================================================================
NOTA: PostgreSQL no permite triggers AFTER SELECT, por lo que la detección
se realiza exclusivamente mediante log parsing (log_statement=all).
=============================================================================
Dependencias:
  pip install psycopg2-binary colorama
=============================================================================
"""

import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

import psycopg2
from colorama import Fore, Style, init

init(autoreset=True)

# -----------------------------------------------------------------------------
# CONFIGURACIÓN
# -----------------------------------------------------------------------------
DB_CONFIG = {
    "host":     "localhost",
    "port":     5433,
    "dbname":   "honeylab",
    "user":     "postgres",
    "password": "SuperAdmin_Lab_2024!",
}

LOG_DIR      = Path(__file__).parent / "logs"
INCIDENT_LOG = Path(__file__).parent / "incidents.jsonl"
HONEYTOKEN_TABLE = "tb_credenciales_vpn_admin"

# Patrón para detectar accesos a la honeytoken en los logs de PostgreSQL
LOG_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[^\]]*)'
    r'\s+\[(?P<pid>\d+)\]'
    r'\s+(?P<user>\S+)@(?P<db>\S+)'
    r'\s+\[(?P<client>[^\]]+)\]'
    r'.*?'
    r'(?P<query>(?:SELECT|select).*?' + HONEYTOKEN_TABLE + r'.*)',
    re.DOTALL
)

# -----------------------------------------------------------------------------
# HELPERS DE OUTPUT
# -----------------------------------------------------------------------------
def banner():
    print(f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║          🍯  HONEYLAB — MONITOR DE DEFENSA ACTIVA  🍯         ║
║         Blue Team Lab | Honeytokens & Auditoría SQL           ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")

def log_info(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{Fore.CYAN}[{ts}] ℹ  {msg}{Style.RESET_ALL}")

def log_ok(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{Fore.GREEN}[{ts}] ✔  {msg}{Style.RESET_ALL}")

def log_alert(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\n{Fore.RED}{'━'*64}")
    print(f"{'🚨'*4}  ALERTA HONEYTOKEN  {'🚨'*4}")
    print(f"[{ts}] {msg}")
    print(f"{'━'*64}{Style.RESET_ALL}\n")

def log_warn(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{Fore.YELLOW}[{ts}] ⚠  {msg}{Style.RESET_ALL}")

# -----------------------------------------------------------------------------
# PERSISTENCIA DE INCIDENTES
# -----------------------------------------------------------------------------
def save_incident(source: str, data: dict):
    incident = {
        "timestamp":  datetime.utcnow().isoformat() + "Z",
        "source":     source,
        "data":       data,
    }
    with open(INCIDENT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(incident, ensure_ascii=False) + "\n")
    log_warn(f"Incidente guardado → {INCIDENT_LOG.name}")

# -----------------------------------------------------------------------------
# NOTA sobre detección en tiempo real
# -----------------------------------------------------------------------------
# PostgreSQL NO permite triggers AFTER SELECT en tablas, por lo que el
# mecanismo de NOTIFY ('honeytoken_alert') no está disponible.
#
# La detección se realiza exclusivamente mediante el parseo de logs
# (log_statement=all en postgresql.conf). Los scripts Python leen el
# archivo de log y detectan accesos a tb_credenciales_vpn_admin por
# expresión regular.
#
# Para una implementación con NOTIFY real, sería necesario:
#   - Extensión pg_audit (vía hooks de evento)
#   - O un proxy SQL intermedio
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# MÓDULO 1: PARSER DE LOGS DE POSTGRESQL
# -----------------------------------------------------------------------------
class LogTailer:
    """
    Sigue el fichero de log de PostgreSQL buscando líneas que contengan
    la tabla honeytoken. Funciona como 'tail -f' con detección de rotación.
    """

    def __init__(self):
        self._file     = None
        self._path     = None
        self._inode    = None
        self._position = 0

    def _get_current_log(self) -> Path | None:
        """Devuelve el fichero de log del día actual."""
        today = datetime.now().strftime("%Y-%m-%d")
        candidates = sorted(LOG_DIR.glob(f"postgresql-{today}*.log"))
        if candidates:
            return candidates[-1]
        # Fallback: el log más reciente disponible
        all_logs = sorted(LOG_DIR.glob("postgresql-*.log"))
        return all_logs[-1] if all_logs else None

    def _open_log(self):
        path = self._get_current_log()
        if path is None:
            return False
        if path != self._path or not self._file:
            if self._file:
                self._file.close()
            self._path     = path
            self._file     = open(path, "r", encoding="utf-8", errors="replace")
            self._inode    = path.stat().st_ino
            self._position = 0
            log_ok(f"Monitorizando log: {path.name}")
        return True

    def read_new_lines(self) -> list[str]:
        if not self._open_log():
            return []
        # Detectar rotación de fichero
        try:
            current_inode = self._path.stat().st_ino
        except FileNotFoundError:
            self._file = None
            return []
        if current_inode != self._inode:
            self._file.close()
            self._file = None
            return self.read_new_lines()

        self._file.seek(self._position)
        lines = self._file.readlines()
        self._position = self._file.tell()
        return lines

def parse_log_lines(lines: list[str]):
    """
    Analiza líneas de log buscando accesos a la honeytoken.
    El formato esperado incluye el log_line_prefix configurado en postgresql.conf.
    """
    for line in lines:
        if HONEYTOKEN_TABLE.lower() not in line.lower():
            continue
        # Extraer campos del prefijo de log: %t [%p] %u@%d [%r] [%i]
        # Ejemplo: 2024-05-21 10:32:45 UTC [142] empleado_sospechoso@honeylab [172.17.0.1:54321] [SELECT]
        ts_match   = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
        user_match = re.search(r'\[\d+\] (\S+)@(\S+) \[', line)
        ip_match   = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):?(\d+)?\]', line)
        query_idx  = line.lower().find("select")

        ts    = ts_match.group(1)   if ts_match   else "N/A"
        user  = user_match.group(1) if user_match else "N/A"
        db    = user_match.group(2) if user_match else "N/A"
        ip    = ip_match.group(1)   if ip_match   else "N/A"
        port  = ip_match.group(2)   if (ip_match and ip_match.group(2)) else "N/A"
        query = line[query_idx:].strip() if query_idx >= 0 else line.strip()

        event = {
            "timestamp": ts,
            "usuario":   user,
            "db":        db,
            "ip":        ip,
            "puerto":    port,
            "query":     query[:500],
        }

        log_alert(
            f"HONEYTOKEN DETECTADA EN LOG\n"
            f"  Usuario   : {Fore.YELLOW}{user}{Fore.RED}\n"
            f"  IP origen : {Fore.YELLOW}{ip}:{port}{Fore.RED}\n"
            f"  Base datos: {db}\n"
            f"  Timestamp : {ts}\n"
            f"  Query     : {Fore.YELLOW}{query[:200]}{Fore.RED}"
        )
        save_incident("LOG_PARSER", event)

# -----------------------------------------------------------------------------
# MÓDULO 3: CONSULTA A tb_audit_log (resumen de incidentes guardados en PG)
# -----------------------------------------------------------------------------
def dump_audit_table():
    """Muestra los eventos registrados en tb_audit_log directamente."""
    log_info("Consultando tb_audit_log en PostgreSQL...")
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            SELECT id, ts, evento, usuario_pg, ip_origen, puerto, 
                   left(query_text, 100) AS query_snippet, tabla
            FROM tb_audit_log
            ORDER BY ts DESC
            LIMIT 20;
        """)
        rows = cur.fetchall()
        conn.close()

        if not rows:
            log_ok("tb_audit_log está vacía — ningún acceso a honeytokens registrado aún.")
            return

        print(f"\n{Fore.MAGENTA}{'═'*64}")
        print(f"  📋 REGISTRO DE AUDITORÍA INTERNA (últimos 20 eventos)")
        print(f"{'═'*64}{Style.RESET_ALL}")
        headers = ["ID", "Timestamp", "Evento", "Usuario", "IP", "Puerto", "Query (100c)", "Tabla"]
        col_w   = [4, 25, 20, 25, 16, 6, 40, 30]
        header_line = "  ".join(h.ljust(w) for h, w in zip(headers, col_w))
        print(f"{Fore.CYAN}{header_line}{Style.RESET_ALL}")
        print("─" * 150)
        for row in rows:
            values = [str(v) if v is not None else "NULL" for v in row]
            print("  ".join(v.ljust(w) for v, w in zip(values, col_w)))
        print()

    except Exception as e:
        log_warn(f"No se pudo consultar tb_audit_log: {e}")

# -----------------------------------------------------------------------------
# LOOP PRINCIPAL
# -----------------------------------------------------------------------------
def main():
    banner()

    log_info(f"Directorio de logs  : {LOG_DIR.resolve()}")
    log_info(f"Fichero de incidentes: {INCIDENT_LOG.resolve()}")
    log_info(f"Tabla honeytoken    : {HONEYTOKEN_TABLE}")
    print()

    if not LOG_DIR.exists():
        log_warn(f"El directorio de logs no existe todavía: {LOG_DIR}")
        log_warn("¿Está corriendo el contenedor Docker? → docker-compose up -d")

    # Mostrar estado inicial de tb_audit_log
    dump_audit_table()

    # Inicializar tailer de logs
    tailer = LogTailer()

    log_info("Monitor activo. Pulsa Ctrl+C para salir.\n")

    try:
        while True:
            # Leer nuevas líneas del log de PostgreSQL
            new_lines = tailer.read_new_lines()
            if new_lines:
                parse_log_lines(new_lines)

            time.sleep(1)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Monitor detenido por el usuario.{Style.RESET_ALL}")
        sys.exit(0)

if __name__ == "__main__":
    main()
