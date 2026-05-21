#!/usr/bin/env python3
"""
=============================================================================
soc_active_defense.py — SOAR Active Defense Response
Laboratorio Blue Team | Deception Technology & Honeytokens
=============================================================================
Lee logs de PostgreSQL en tiempo real (modo tail). Cuando detecta que
ALGUIEN (excepto el administrador postgres) ejecutó una consulta contra
la tabla honeytoken tb_credenciales_vpn_admin:

  1. Imprime una ALERTA CRÍTICA con el usuario infractor.
  2. Se conecta como administrador y ejecuta:
       REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM <user>;
     Esto aísla al atacante de forma inmediata (Active Defense).

No vuelve a aislar al mismo usuario dos veces.

Modo de uso:
  python soc_active_defense.py

Dependencias:
  pip install psycopg2-binary colorama

Ejecución recomendada:
  Terminal 1: docker-compose up -d
  Terminal 2: python monitor_honeylab.py        ← alertas en tiempo real
  Terminal 3: python traffic_simulator.py        ← genera tráfico
  Terminal 4: python soc_active_defense.py       ← SOAR: detecta + aísla
=============================================================================
"""

import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Set

import psycopg2
from colorama import Fore, Style, init

init(autoreset=True)

# =============================================================================
# CONFIGURACIÓN
# =============================================================================

LOG_DIR = Path(__file__).parent / "logs"
LOG_GLOB = "postgresql-*.log"

HONEYTOKEN_TABLE = "tb_credenciales_vpn_admin"

# Usuarios exentos de aislamiento (el admin del sistema)
EXEMPT_USERS: Set[str] = {"postgres"}

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "port": int(os.environ.get("DB_PORT", "5433")),
    "dbname": os.environ.get("DB_NAME", "honeylab"),
    "user": "postgres",
    "password": "SuperAdmin_Lab_2024!",
    "connect_timeout": 5,
}

POLL_INTERVAL = 1  # segundos entre lecturas del log

# =============================================================================
# REGEX: parseo del log_line_prefix de PostgreSQL
# -----------------------------------------------------------------------------
# log_line_prefix configurado en postgresql.conf:
#   '%t [%p] %u@%d [%r] [%i] '
#
# Produce líneas como:
#   2024-05-22 14:30:00.123 UTC [12345] empleado_sospechoso@honeylab
#     [172.17.0.1:54321] [SELECT] LOG:  statement: SELECT * FROM tb_...;
# =============================================================================

LOG_PREFIX_RE = re.compile(
    r"^"
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \S+) "  # 1: timestamp
    r"\[(\d+)\] "                                                # 2: pid
    r"(\S+)@(\S+) "                                              # 3: user, 4: db
    r"\[([^\]]+)\] "                                             # 5: cliente IP:puerto
    r"\[(\w+)\] "                                                # 6: comando (SELECT, INSERT…)
)

# Patrón para extraer la query después de "LOG:  statement:"
STMT_RE = re.compile(r"LOG:\s*statement:\s*(.*)", re.DOTALL)

# =============================================================================
# ESTADO GLOBAL
# =============================================================================

# Usuarios que ya fueron aislados (no revocar dos veces)
_revoked_users: Set[str] = set()

# Buffer para queries multilínea (el log de PG parte queries largas en
# varias líneas físicas; las líneas que NO matchean LOG_PREFIX_RE son
# continuación del entry anterior).
_buffer_user: Optional[str] = None
_buffer_query_parts: list[str] = []
_buffer_in_statement: bool = False

# Conexión admin reutilizable
_conn_admin: Optional[psycopg2.extensions.connection] = None

# =============================================================================
# HELPERS DE OUTPUT
# =============================================================================

def timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def banner() -> None:
    print(f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║  🛡️  SOC ACTIVE DEFENSE — SOAR Automatic Response  🛡️    ║
║  Detección + Aislamiento en tiempo real                  ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")
    print(f"  {Fore.RED}Modo:{Style.RESET_ALL}        Tail de logs → Regex → Active Response")
    print(f"  {Fore.RED}Cebo vigilado:{Style.RESET_ALL} {HONEYTOKEN_TABLE}")
    print(f"  {Fore.RED}Exentos:{Style.RESET_ALL}      {', '.join(sorted(EXEMPT_USERS))}")
    print(f"  {Fore.RED}Acción:{Style.RESET_ALL}       REVOKE ALL PRIVILEGES ON ALL TABLES")
    print(f"  {Fore.RED}Logs:{Style.RESET_ALL}         {LOG_DIR.resolve()}")
    print(f"\n{Fore.YELLOW}{'═' * 66}{Style.RESET_ALL}\n")


def log_info(msg: str) -> None:
    print(f"{Fore.CYAN}[{timestamp()}] ℹ  {msg}{Style.RESET_ALL}")


def log_ok(msg: str) -> None:
    print(f"{Fore.GREEN}[{timestamp()}] ✔  {msg}{Style.RESET_ALL}")


def log_warn(msg: str) -> None:
    print(f"{Fore.YELLOW}[{timestamp()}] ⚠  {msg}{Style.RESET_ALL}")


def print_alerta_critica(user: str, query: str, ip: str) -> None:
    print(f"""
{Fore.RED}{'█' * 66}
██  🚨  ALERTA CRÍTICA — HONEYTOKEN DETECTADA  🚨  ██
{'█' * 66}
  {Fore.YELLOW}Usuario infractor:{Fore.RED}  {user}
  {Fore.YELLOW}IP origen:{Fore.RED}          {ip}
  {Fore.YELLOW}Query detectada:{Fore.RED}
    {query[:300]}
{'█' * 66}{Style.RESET_ALL}
""")


def print_respuesta_activa(user: str, success: bool) -> None:
    if success:
        print(f"""
{Fore.GREEN}{'█' * 66}
██  ✅  RESPUESTA ACTIVA EJECUTADA — USUARIO AISLADO  ✅  ██
{'█' * 66}
  {Fore.YELLOW}Usuario:{Fore.GREEN}        {user}
  {Fore.YELLOW}Acción:{Fore.GREEN}         REVOKE ALL PRIVILEGES ON ALL TABLES
                 IN SCHEMA public FROM {user}
  {Fore.YELLOW}Estado:{Fore.GREEN}         AISLADO — el atacante perdió todo acceso
{'█' * 66}{Style.RESET_ALL}
""")
    else:
        print(f"""
{Fore.RED}{'█' * 66}
██  ❌  RESPUESTA ACTIVA FALLIDA  ❌                   ██
{'█' * 66}
  {Fore.YELLOW}Usuario:{Fore.RED}        {user}
  {Fore.YELLOW}Acción:{Fore.RED}         REVOKE ALL PRIVILEGES — ERROR
  {Fore.YELLOW}Estado:{Fore.RED}         Revisar conexión con la base de datos
{'█' * 66}{Style.RESET_ALL}
""")


# =============================================================================
# CONEXIÓN ADMIN
# =============================================================================

def get_admin_conn() -> Optional[psycopg2.extensions.connection]:
    """
    Retorna una conexión reutilizable como postgres (superusuario).
    Si la conexión actual está cerrada o nunca existió, crea una nueva.
    """
    global _conn_admin
    try:
        if _conn_admin is None or _conn_admin.closed:
            _conn_admin = psycopg2.connect(**DB_CONFIG)
            _conn_admin.set_session(autocommit=True)
            log_ok("Conectado como administrador a PostgreSQL.")
        return _conn_admin
    except psycopg2.OperationalError as e:
        log_warn(f"No se pudo conectar como administrador: {e}")
        return None


# =============================================================================
# RESPUESTA ACTIVA — REVOCACIÓN DE PRIVILEGIOS
# =============================================================================

def aislar_usuario(user: str) -> bool:
    """
    Ejecuta la respuesta activa:
      1. REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM user
      2. REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM user
      3. REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM user

    Retorna True si la operación fue exitosa.
    No vuelve a aislar usuarios ya procesados.
    """
    # ── Protección: no revocar dos veces ──
    if user in _revoked_users:
        log_info(f"{user} ya fue aislado anteriormente. Omitiendo.")
        return True

    conn = get_admin_conn()
    if conn is None:
        return False

    try:
        with conn.cursor() as cur:
            # Revocar en tablas
            cur.execute(
                "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM %s",
                (user,)
            )
            # Revocar en secuencias
            cur.execute(
                "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM %s",
                (user,)
            )
            # Revocar en funciones
            cur.execute(
                "REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM %s",
                (user,)
            )
            # Revocar en la base de datos (CONNECT no se toca para que vea el error)
            log_ok(f"Privilegios revocados exitosamente para {user}.")

        _revoked_users.add(user)
        return True

    except psycopg2.Error as e:
        log_warn(f"Error ejecutando REVOKE para {user}: {e}")
        return False


# =============================================================================
# PARSER DE LOGS MULTILÍNEA
# =============================================================================

def _flush_buffer() -> None:
    """
    Procesa el buffer de query multilínea acumulado.
    Si el usuario no es admin y la query contiene el nombre de la tabla
    honeytoken, se gatilla la respuesta activa.
    Se llama al inicio de cada nuevo log entry y al final del archivo.
    """
    global _buffer_user, _buffer_query_parts, _buffer_in_statement

    if not _buffer_in_statement or _buffer_user is None:
        return

    # Ensamblar la query completa (puede venir en varias líneas)
    full_query = " ".join(p.strip() for p in _buffer_query_parts if p.strip())
    full_query = full_query.strip()

    if not full_query:
        _reset_buffer()
        return

    # ─── ¿La query contiene el nombre de la honeytoken? ───
    if HONEYTOKEN_TABLE.lower() not in full_query.lower():
        _reset_buffer()
        return

    # ─── ¿El usuario está exento? (postgres) ───
    if _buffer_user in EXEMPT_USERS:
        log_info(f"Usuario exento {_buffer_user} consultó la honeytoken (no se toma acción).")
        _reset_buffer()
        return

    # ─── ¡ALERTA! Usuario no autorizado tocó el cebo ───
    print_alerta_critica(
        user=_buffer_user,
        query=full_query,
        ip="(desde log — ver línea completa)",
    )

    # ─── RESPUESTA ACTIVA: AISLAR AL INTRUSO ───
    exito = aislar_usuario(_buffer_user)
    print_respuesta_activa(user=_buffer_user, success=exito)

    # Si no se pudo aislar, reintentar una vez más con conexión nueva
    if not exito:
        log_warn(f"Reintentando aislamiento de {_buffer_user} en 5 segundos…")
        time.sleep(5)
        global _conn_admin
        if _conn_admin and not _conn_admin.closed:
            try:
                _conn_admin.close()
            except Exception:
                pass
        _conn_admin = None
        exito = aislar_usuario(_buffer_user)
        if exito:
            print_respuesta_activa(user=_buffer_user, success=True)

    _reset_buffer()


def _reset_buffer() -> None:
    global _buffer_user, _buffer_query_parts, _buffer_in_statement
    _buffer_user = None
    _buffer_query_parts = []
    _buffer_in_statement = False


def procesar_linea(line: str) -> None:
    """
    Procesa una línea del log de PostgreSQL.
    - Si es un nuevo entry (matchea LOG_PREFIX_RE):
        → flushea el buffer anterior
        → si es un statement, inicia buffer nuevo
    - Si NO matchea el prefijo → es continuación multilínea del entry actual.
    """
    global _buffer_user, _buffer_query_parts, _buffer_in_statement

    match = LOG_PREFIX_RE.match(line)
    if match:
        # ── Nuevo log entry: flushear el anterior ──
        _flush_buffer()

        # ── Extraer usuario ──
        usuario = match.group(3)

        # ── ¿El resto de la línea contiene un statement SQL? ──
        remainder = line[match.end():]
        stmt_match = STMT_RE.match(remainder)

        if stmt_match:
            _buffer_user = usuario
            _buffer_query_parts = [stmt_match.group(1)]
            _buffer_in_statement = True
        else:
            # No es un statement o no nos interesa
            _buffer_in_statement = False
            _buffer_user = None
            _buffer_query_parts = []
    else:
        # ── Línea de continuación (multilínea) ──
        if _buffer_in_statement and line.strip():
            _buffer_query_parts.append(line.strip())


# =============================================================================
# TAILER DE LOGS (similar al de monitor_honeylab.py)
# =============================================================================

class LogTailer:
    """
    Sigue el fichero de log de PostgreSQL más reciente.
    Soporta rotación de ficheros.
    """

    def __init__(self):
        self._file: Optional[object] = None
        self._path: Optional[Path] = None
        self._inode: Optional[int] = None
        self._position: int = 0

    def _get_current_log(self) -> Optional[Path]:
        """Devuelve el fichero de log del día actual o el más reciente."""
        today = datetime.now().strftime("%Y-%m-%d")
        candidates = sorted(LOG_DIR.glob(f"postgresql-{today}*.log"))
        if candidates:
            return candidates[-1]
        all_logs = sorted(LOG_DIR.glob(LOG_GLOB))
        return all_logs[-1] if all_logs else None

    def _open_log(self) -> bool:
        path = self._get_current_log()
        if path is None:
            return False
        if path != self._path or self._file is None:
            if self._file:
                self._file.close()
            self._path = path
            # Abrir en modo lectura, empezando desde el final
            self._file = open(path, "r", encoding="utf-8", errors="replace")
            self._inode = path.stat().st_ino
            # Ir al final para no releer líneas viejas
            self._file.seek(0, 2)
            self._position = self._file.tell()
            log_ok(f"Vigilando log: {path.name}")
        return True

    def read_new_lines(self) -> list[str]:
        if not self._open_log():
            return []

        # Detectar rotación de fichero
        try:
            current_inode = self._path.stat().st_ino  # type: ignore[union-attr]
        except FileNotFoundError:
            self._file = None
            return []
        if current_inode != self._inode:
            self._file.close()  # type: ignore[union-attr]
            self._file = None
            log_info("Log rotado. Abriendo nuevo fichero…")
            return self.read_new_lines()

        # Leer líneas nuevas
        self._file.seek(self._position)  # type: ignore[union-attr]
        lines = self._file.readlines()
        self._position = self._file.tell()
        return lines


# =============================================================================
# LOOP PRINCIPAL
# =============================================================================

def main() -> None:
    banner()

    # Verificar que el directorio de logs existe
    if not LOG_DIR.exists():
        log_warn(f"Directorio de logs no encontrado: {LOG_DIR}")
        log_warn("¿Está corriendo el contenedor? → docker-compose up -d")
        log_info("Esperando logs…")
    else:
        log_info(f"Directorio de logs detectado: {LOG_DIR.resolve()}")

    # Probar conexión admin
    admin_conn = get_admin_conn()
    if admin_conn is None:
        log_warn("No se pudo conectar como administrador. Reintentando en background…")

    tailer = LogTailer()
    log_info("Active Defense activo. Pulsa Ctrl+C para salir.\n")

    try:
        while True:
            lines = tailer.read_new_lines()
            for line in lines:
                try:
                    procesar_linea(line)
                except Exception as e:
                    log_warn(f"Error inesperado procesando línea: {e}")

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        # Flushear buffer pendiente antes de salir
        try:
            _flush_buffer()
        except Exception:
            pass
        print(f"\n{Fore.YELLOW}[{timestamp()}] Active Defense detenido por el usuario.{Style.RESET_ALL}")
        if _conn_admin and not _conn_admin.closed:
            _conn_admin.close()
            log_info("Conexión admin cerrada.")
        usuarios_aislados = len(_revoked_users)
        if usuarios_aislados > 0:
            log_info(f"Usuarios aislados durante la sesión: {usuarios_aislados}")
            for u in sorted(_revoked_users):
                print(f"    → {Fore.RED}{u}{Style.RESET_ALL}")
        else:
            log_info("No se aisló ningún usuario en esta sesión.")
        print(f"{Fore.GREEN}[{timestamp()}] ¡Hasta la próxima, man!{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == "__main__":
    main()
