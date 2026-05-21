#!/usr/bin/env python3
"""
=============================================================================
traffic_simulator.py — Generador de Tráfico SQL para Honeylab
Laboratorio Blue Team | Deception Technology & Honeytokens
=============================================================================
Simula comportamiento de usuarios en la base de datos honeylab:

  - 95%  → empleado_normal realiza consultas SELECT legítimas
           (tb_clientes, tb_facturacion) simulando trabajo diario.
  -  5%  → empleado_sospechoso ejecuta SELECT * FROM tb_credenciales_vpn_admin
           (cae en el honeytoken → activa NOTIFY + tb_audit_log + logs).

Modo de uso:
  python traffic_simulator.py

Dependencias:
  pip install psycopg2-binary colorama

Recomendación:
  Ejecutarlo en una terminal separada, en paralelo con monitor_honeylab.py
  para ver las alertas en tiempo real cuando el usuario sospechoso muerda el cebo.
=============================================================================
"""

import os
import random
import sys
import time
from datetime import datetime
from typing import Optional

import psycopg2
from colorama import Fore, Style, init

init(autoreset=True)

# -----------------------------------------------------------------------------
# CONFIGURACIÓN
# -----------------------------------------------------------------------------
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5433"))
DB_NAME = os.environ.get("DB_NAME", "honeylab")

USERS = {
    "normal": {
        "user": "empleado_normal",
        "pass": "P@ssw0rd_Normal_2024!",
        "label": "empleado_normal",
    },
    "sospechoso": {
        "user": "empleado_sospechoso",
        "pass": "P@ssw0rd_Sospech_2024!",
        "label": "empleado_sospechoso",
    },
}

# Probabilidad de que el próximo query sea del usuario sospechoso tocando el cebo
HONEYTOKEN_PROB = 0.05  # 5%

# Pausa mínima y máxima entre consultas (segundos) — para que parezca actividad humana
PAUSA_MIN = 1.5
PAUSA_MAX = 5.0

# -----------------------------------------------------------------------------
# REPERTORIO DE CONSULTAS LEGÍTIMAS (empleado_normal)
# -----------------------------------------------------------------------------
QUERIES_NORMAL = [
    # Lecturas simples
    "SELECT * FROM tb_clientes LIMIT 5;",
    "SELECT * FROM tb_clientes LIMIT 10;",
    "SELECT * FROM tb_facturacion LIMIT 10;",
    "SELECT * FROM tb_facturacion LIMIT 20;",
    "SELECT COUNT(*) AS total_clientes FROM tb_clientes;",
    "SELECT COUNT(*) AS total_facturas FROM tb_facturacion;",
    # Filtros por segmento / estado
    "SELECT * FROM tb_clientes WHERE segmento = 'PREMIUM';",
    "SELECT * FROM tb_clientes WHERE segmento = 'ESTANDAR';",
    "SELECT * FROM tb_clientes WHERE segmento = 'BASICO' AND activo = TRUE;",
    "SELECT * FROM tb_facturacion WHERE estado = 'PENDIENTE';",
    "SELECT * FROM tb_facturacion WHERE estado = 'VENCIDA';",
    "SELECT * FROM tb_facturacion WHERE estado = 'PAGADA' ORDER BY fecha_emision DESC LIMIT 10;",
    # Agregaciones de negocio
    """SELECT segmento, COUNT(*) AS cantidad
       FROM tb_clientes
       GROUP BY segmento
       ORDER BY cantidad DESC;""",
    """SELECT estado, COUNT(*) AS cantidad, SUM(importe_total) AS total_acumulado
       FROM tb_facturacion
       GROUP BY estado
       ORDER BY total_acumulado DESC;""",
    # Facturación reciente
    "SELECT * FROM tb_facturacion ORDER BY fecha_emision DESC LIMIT 5;",
    # Clientes recién dados de alta
    "SELECT * FROM tb_clientes ORDER BY fecha_alta DESC LIMIT 5;",
    # Búsqueda por cliente (JOIN ligero)
    """SELECT c.nombre, c.apellidos, c.email,
            f.numero_factura, f.importe_total, f.estado
     FROM tb_clientes c
     JOIN tb_facturacion f ON f.cliente_id = c.id
     WHERE c.activo = TRUE
     ORDER BY f.fecha_emision DESC
     LIMIT 15;""",
    # Facturación > 1000 €
    """SELECT * FROM tb_facturacion
       WHERE importe_neto > 1000
       ORDER BY importe_neto DESC;""",
    # Clientes sin facturación (LEFT JOIN)
    """SELECT c.id, c.nombre, c.email
       FROM tb_clientes c
       LEFT JOIN tb_facturacion f ON f.cliente_id = c.id
       WHERE f.id IS NULL;""",
    # Top clientes por importe facturado
    """SELECT c.nombre, c.apellidos, SUM(f.importe_total) AS gasto_total
       FROM tb_clientes c
       JOIN tb_facturacion f ON f.cliente_id = c.id
       GROUP BY c.id, c.nombre, c.apellidos
       ORDER BY gasto_total DESC
       LIMIT 5;""",
    # Facturación media por segmento
    """SELECT c.segmento,
            ROUND(AVG(f.importe_total), 2) AS ticket_medio
       FROM tb_facturacion f
       JOIN tb_clientes c ON c.id = f.cliente_id
       GROUP BY c.segmento
       ORDER BY ticket_medio DESC;""",
    # Facturas vencidas con datos del cliente
    """SELECT c.nombre, c.apellidos, c.telefono,
            f.numero_factura, f.importe_total, f.fecha_emision
       FROM tb_facturacion f
       JOIN tb_clientes c ON c.id = f.cliente_id
       WHERE f.estado = 'VENCIDA';""",
    # Conteo de facturas por mes
    """SELECT TO_CHAR(fecha_emision, 'YYYY-MM') AS mes,
            COUNT(*) AS facturas, SUM(importe_total) AS ingresos
       FROM tb_facturacion
       GROUP BY mes
       ORDER BY mes DESC
       LIMIT 12;""",
]

QUERY_HONEYTOKEN = "SELECT * FROM tb_credenciales_vpn_admin;"

# Estadísticas acumuladas
STATS = {"total": 0, "normales": 0, "honeytoken": 0, "errores": 0}


# -----------------------------------------------------------------------------
# HELPERS DE OUTPUT (misma convención que monitor_honeylab.py)
# -----------------------------------------------------------------------------
def timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def banner() -> None:
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║     🚦  TRAFFIC SIMULATOR — Generador de Tráfico SQL  🚦    ║
║     Laboratorio Honeytokens | Deception Technology          ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")
    print(f"  {Fore.CYAN}DB:{Style.RESET_ALL}        {DB_HOST}:{DB_PORT}/{DB_NAME}")
    print(f"  {Fore.CYAN}Usuarios:{Style.RESET_ALL}     {USERS['normal']['user']} (95%) + {USERS['sospechoso']['user']} (5%)")
    print(f"  {Fore.CYAN}Pausas:{Style.RESET_ALL}      {PAUSA_MIN}s – {PAUSA_MAX}s entre consultas")
    print(f"  {Fore.CYAN}Cebo:{Style.RESET_ALL}        tb_credenciales_vpn_admin")
    print(f"  {Fore.CYAN}Monitor:{Style.RESET_ALL}     Ejecutá monitor_honeylab.py en otra terminal para ver alertas\n")
    print(f"{Fore.YELLOW}{'═' * 66}{Style.RESET_ALL}\n")


def log_normal(user: str, query: str) -> None:
    ts = timestamp()
    snippet = query.replace("\n", " ").strip()
    if len(snippet) > 100:
        snippet = snippet[:97] + "..."
    print(f"{Fore.GREEN}[{ts}] ✓ {user}{Style.RESET_ALL}  {snippet}")


def log_honeytoken(user: str, query: str) -> None:
    ts = timestamp()
    print(f"\n{Fore.RED}{'⚠' * 4}  HONEYTOKEN ACTIVADO  {'⚠' * 4}")
    print(f"[{ts}] {Fore.YELLOW}{user}{Fore.RED} ejecutó:")
    print(f"  {Fore.YELLOW}{query.strip()}{Style.RESET_ALL}")
    print(f"{Fore.RED}{'⚠' * 48}{Style.RESET_ALL}\n")


def log_error(user: str, err: str) -> None:
    ts = timestamp()
    print(f"{Fore.RED}[{ts}] ✗ {user}  ERROR: {err}{Style.RESET_ALL}")


def log_stats() -> None:
    """Muestra estadísticas acumuladas y las resetea."""
    total = STATS["total"]
    if total == 0:
        return
    pct_honey = (STATS["honeytoken"] / total) * 100
    pct_err   = (STATS["errores"] / total) * 100
    print(f"\n{Fore.CYAN}{'─' * 50}")
    print(f"  📊  ESTADÍSTICAS — {total} consultas ejecutadas")
    print(f"{'─' * 50}")
    print(f"  Normales    : {STATS['normales']:>5}  ({100 * STATS['normales'] // total if total else 0:>3}%)")
    print(f"  Honeytoken  : {Fore.RED if STATS['honeytoken'] > 0 else Fore.GREEN}"
          f"{STATS['honeytoken']:>5}  ({pct_honey:5.1f}%){Style.RESET_ALL}")
    print(f"  Errores     : {Fore.YELLOW if STATS['errores'] > 0 else Fore.GREEN}"
          f"{STATS['errores']:>5}  ({pct_err:5.1f}%){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─' * 50}{Style.RESET_ALL}\n")


# -----------------------------------------------------------------------------
# CONEXIONES A POSTGRESQL
# -----------------------------------------------------------------------------
def conectar(perfil: str) -> Optional[psycopg2.extensions.connection]:
    """
    Crea una conexión a PostgreSQL con las credenciales del perfil indicado.
    Retorna None si falla (para que el loop principal reintente después).
    """
    creds = USERS[perfil]
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=creds["user"],
            password=creds["pass"],
            connect_timeout=5,
        )
        conn.set_session(autocommit=True)  # Cada query se ejecuta y commitea sola
        return conn
    except psycopg2.OperationalError as e:
        log_error(creds["user"], str(e))
        return None


# -----------------------------------------------------------------------------
# EJECUTOR DE CONSULTAS
# -----------------------------------------------------------------------------
def ejecutar_query(conn: psycopg2.extensions.connection, query: str) -> None:
    """Ejecuta una query y consume el resultado."""
    try:
        with conn.cursor() as cur:
            cur.execute(query)
            # Consumir todas las filas para evitar "queued query" pendiente
            if cur.description:
                cur.fetchall()  # Consumir todas las filas
    except Exception as e:
        raise


# -----------------------------------------------------------------------------
# LOOP PRINCIPAL
# -----------------------------------------------------------------------------
def main() -> None:
    banner()

    # Contador para mostrar estadísticas cada N consultas
    STATS_INTERVAL = 50
    last_stats = 0

    # Pool de conexiones recicladas para no abrir/cerrar en cada iteración
    conn_normal: Optional[psycopg2.extensions.connection] = None
    conn_sospechoso: Optional[psycopg2.extensions.connection] = None

    try:
        while True:
            # ─── Decidir acción: ¿usuario normal o sospechoso? ───
            es_honeytoken = random.random() < HONEYTOKEN_PROB

            if es_honeytoken:
                perfil = "sospechoso"
                query = QUERY_HONEYTOKEN
            else:
                perfil = "normal"
                query = random.choice(QUERIES_NORMAL)

            creds = USERS[perfil]
            conn = conn_sospechoso if perfil == "sospechoso" else conn_normal

            # ─── Verificar / reciclar conexión ───
            if conn is None or conn.closed:
                conn = conectar(perfil)
                if conn is None:
                    STATS["errores"] += 1
                    # Esperar y reintentar
                    time.sleep(5)
                    continue
                # Guardar la conexión en el pool
                if perfil == "sospechoso":
                    conn_sospechoso = conn
                else:
                    conn_normal = conn

            # ─── Ejecutar query ───
            try:
                ejecutar_query(conn, query)
                STATS["total"] += 1
                if es_honeytoken:
                    STATS["honeytoken"] += 1
                    log_honeytoken(creds["user"], query)
                else:
                    STATS["normales"] += 1
                    log_normal(creds["user"], query)
            except (psycopg2.OperationalError, psycopg2.DatabaseError) as e:
                STATS["errores"] += 1
                log_error(creds["user"], str(e)[:120])
                # Marcar conexión como muerta para que se recicle
                if perfil == "sospechoso":
                    if conn_sospechoso and not conn_sospechoso.closed:
                        conn_sospechoso.close()
                    conn_sospechoso = None
                else:
                    if conn_normal and not conn_normal.closed:
                        conn_normal.close()
                    conn_normal = None
                time.sleep(3)
                continue

            # ─── Estadísticas periódicas ───
            if STATS["total"] - last_stats >= STATS_INTERVAL:
                last_stats = STATS["total"]
                log_stats()

            # ─── Pausa realista ───
            pausa = random.uniform(PAUSA_MIN, PAUSA_MAX)
            time.sleep(pausa)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[{timestamp()}] Simulador detenido por el usuario.{Style.RESET_ALL}")
        log_stats()
        for conn in (conn_normal, conn_sospechoso):
            if conn and not conn.closed:
                conn.close()
        print(f"{Fore.GREEN}[{timestamp()}] Conexiones cerradas. ¡Hasta la próxima, man!{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == "__main__":
    main()
