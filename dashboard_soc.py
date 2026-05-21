#!/usr/bin/env python3
"""
=============================================================================
dashboard_soc.py — SOC Dashboard Web | Honeylab
Flask + Server-Sent Events | Laboratorio Honeytokens & Defensa Activa
=============================================================================
Una sola pantalla dividida en dos paneles en tiempo real:

  ┌──────────────────────────────┬──────────────────────────────┐
  │  🖥️  TRÁFICO EN DIRECTO      │  🛡️  ALERTAS Y RESPUESTA    │
  │                              │                              │
  │  Feed de consultas SQL       │  Detección de intrusos +    │
  │  ejecutadas por              │  respuesta activa del SOAR  │
  │  empleado_normal             │  (REVOKE automático)        │
  │                              │                              │
  │  [✓] SELECT * FROM tb_cli…  │  [🚨] HONEYTOKEN ACCEDIDA   │
  │  [✓] SELECT COUNT(*) FROM…  │       usuario: empleado_sos… │
  │  [✓] SELECT c.nombre, c.…  │  [✅] Permisos revocados —   │
  │                              │       Amenaza contenida     │
  └──────────────────────────────┴──────────────────────────────┘

Modo de uso:
  python dashboard_soc.py

  Abrir en navegador: http://localhost:5001 (o el puerto mapeado en docker-compose)

Dependencias:
  pip install flask psycopg2-binary

Ejecución recomendada:
  Terminal 1: docker-compose up -d
  Terminal 2: python traffic_simulator.py
  Terminal 3: python dashboard_soc.py
  (monitor_honeylab.py y soc_active_defense.py son opcionales)
=============================================================================
"""

import json
import os
import re
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from queue import Queue, Empty
from typing import Optional, Set

import psycopg2
from flask import Flask, Response, render_template_string, jsonify

# =============================================================================
# CONFIGURACIÓN
# =============================================================================

LOG_DIR = Path(__file__).parent / "logs"
LOG_GLOB = "postgresql-*.log"

HONEYTOKEN_TABLE = "tb_credenciales_vpn_admin"
EXEMPT_USERS: Set[str] = {"postgres"}

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "port": int(os.environ.get("DB_PORT", "5433")),
    "dbname": os.environ.get("DB_NAME", "honeylab"),
    "user": "postgres",
    "password": "SuperAdmin_Lab_2024!",
    "connect_timeout": 5,
}

POLL_INTERVAL = 0.5  # segundos entre lecturas (semi-tiempo real)
SSE_KEEPALIVE = 15   # segundos entre heartbeats SSE

FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5001  # Coincide con docker-compose (5001:5001). Si usás local sin Docker, usá este mismo puerto

# =============================================================================
# REGEX: log_line_prefix de PostgreSQL
#   '%t [%p] %u@%d [%r] [%i] '
# =============================================================================

LOG_PREFIX_RE = re.compile(
    r"^"
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \S+) "  # 1: timestamp
    r"\[(\d+)\] "                                                # 2: pid
    r"(\S+)@(\S+) "                                              # 3: user, 4: db
    r"\[([^\]]+)\] "                                             # 5: cliente IP:puerto
    r"\[(\w+)\] "                                                # 6: comando
)

STMT_RE = re.compile(r"LOG:\s*statement:\s*(.*)", re.DOTALL)

# =============================================================================
# COLAS SSE
# =============================================================================

traffic_queue: Queue = Queue()
alert_queue: Queue = Queue()

# =============================================================================
# ESTADO GLOBAL
# =============================================================================

_revoked_users: Set[str] = set()
_conn_admin: Optional[psycopg2.extensions.connection] = None

# Contadores para la UI
_stats = {"total_queries": 0, "honeytoken_hits": 0, "revoked_users": 0}

# =============================================================================
# FUNCIONES AUXILIARES
# =============================================================================

def timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def timestamp_iso() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


# =============================================================================
# CONEXIÓN ADMIN (para ejecutar REVOKE)
# =============================================================================

def get_admin_conn() -> Optional[psycopg2.extensions.connection]:
    global _conn_admin
    try:
        if _conn_admin is None or _conn_admin.closed:
            _conn_admin = psycopg2.connect(**DB_CONFIG)
            _conn_admin.set_session(autocommit=True)
        return _conn_admin
    except psycopg2.OperationalError as e:
        print(f"[{timestamp()}] [ADMIN] Error de conexion: {e}", flush=True)
        return None


# =============================================================================
# RESPUESTA ACTIVA — REVOKE
# =============================================================================

def aislar_usuario(user: str) -> bool:
    if user in _revoked_users:
        return True

    conn = get_admin_conn()
    if conn is None:
        port_info = f"{DB_CONFIG['host']}:{DB_CONFIG['port']}"
        print(f"[{timestamp()}] [ADMIN] No se pudo conectar a {port_info} para revocar a {user}", flush=True)
        return False

    try:
        with conn.cursor() as cur:
            cur.execute(
                "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM %s",
                (user,),
            )
            cur.execute(
                "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM %s",
                (user,),
            )
            cur.execute(
                "REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM %s",
                (user,),
            )
        _revoked_users.add(user)
        _stats["revoked_users"] = len(_revoked_users)
        print(f"[{timestamp()}] [ADMIN] Privilegios revocados exitosamente para {user}", flush=True)
        return True
    except psycopg2.Error as e:
        print(f"[{timestamp()}] [ADMIN] Error ejecutando REVOKE para {user}: {e}", flush=True)
        return False


# =============================================================================
# PARSER DE LOGS (multilínea, mismo patrón que soc_active_defense.py)
# =============================================================================

class LogParser:
    """Estado del parser para queries multilínea."""

    def __init__(self):
        self.user: Optional[str] = None
        self.query_parts: list[str] = []
        self.in_statement: bool = False
        self.client_ip: str = ""

    def reset(self) -> None:
        self.user = None
        self.query_parts = []
        self.in_statement = False
        self.client_ip = ""

    def feed_line(self, line: str) -> Optional[dict]:
        """
        Procesa una línea de log.
        Retorna un dict con 'type' ('traffic' | 'honeytoken') si se completó
        un evento, o None si todavía está acumulando.
        """
        match = LOG_PREFIX_RE.match(line)

        if match:
            # ── Nuevo entry: procesar el buffer anterior ──
            result = self._flush()

            # ── Iniciar nuevo buffer ──
            usuario = match.group(3)
            client_ip = match.group(5).split(":")[0] if ":" in match.group(5) else match.group(5)
            remainder = line[match.end():]
            stmt_match = STMT_RE.match(remainder)

            if stmt_match:
                self.user = usuario
                self.client_ip = client_ip
                self.query_parts = [stmt_match.group(1)]
                self.in_statement = True
            else:
                self.in_statement = False

            return result

        # ── Línea de continuación ──
        if self.in_statement and line.strip():
            self.query_parts.append(line.strip())

        return None

    def _flush(self) -> Optional[dict]:
        """Flushea el buffer actual. Retorna un evento si corresponde."""
        if not self.in_statement or self.user is None:
            return None

        full_query = " ".join(p.strip() for p in self.query_parts if p.strip()).strip()
        if not full_query:
            return None

        es_honeytoken = HONEYTOKEN_TABLE.lower() in full_query.lower()
        es_exento = self.user in EXEMPT_USERS

        if es_honeytoken and not es_exento:
            # ── ALERTA: alguien tocó el cebo ──
            exito = aislar_usuario(self.user)
            return {
                "type": "honeytoken",
                "timestamp": timestamp(),
                "ts_iso": timestamp_iso(),
                "user": self.user,
                "ip": self.client_ip,
                "query": full_query[:300],
                "revoked": exito,
            }
        elif not es_honeytoken:
            # ── Tráfico normal ──
            return {
                "type": "traffic",
                "timestamp": timestamp(),
                "ts_iso": timestamp_iso(),
                "user": self.user,
                "ip": self.client_ip,
                "query": full_query[:200],
            }

        return None

    def flush_final(self) -> Optional[dict]:
        """Flushear al finalizar (Ctrl+C)."""
        return self._flush()


# =============================================================================
# TAILER DE LOGS (thread de background)
# =============================================================================

class LogTailer:
    """Sigue el fichero de log más reciente con soporte de rotación."""

    def __init__(self):
        self._file: Optional[object] = None
        self._path: Optional[Path] = None
        self._inode: Optional[int] = None
        self._position: int = 0
        self._parser = LogParser()

    def _get_current_log(self) -> Optional[Path]:
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
            self._file = open(path, "r", encoding="utf-8", errors="replace")
            self._inode = path.stat().st_ino
            # Ir al final para no releer líneas viejas
            self._file.seek(0, 2)
            self._position = self._file.tell()
        return True

    def read_new_lines(self) -> list[str]:
        if not self._open_log():
            return []
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

    def process_lines(self, lines: list[str]) -> None:
        """Procesa líneas y encola eventos en las colas SSE."""
        global _stats
        for line in lines:
            event = self._parser.feed_line(line)
            if event is None:
                continue

            if event["type"] == "traffic":
                _stats["total_queries"] += 1
                traffic_queue.put(event)
            elif event["type"] == "honeytoken":
                _stats["honeytoken_hits"] += 1
                # El evento de honeytoken va a la cola de alertas
                alert_queue.put(event)
                # También mostrar la query en tráfico pero marcada
                event_copy = dict(event)
                event_copy["type"] = "honeytoken_traffic"
                traffic_queue.put(event_copy)


# =============================================================================
# THREAD DE BACKGROUND: LOG TAILING
# =============================================================================

def background_log_reader() -> None:
    """Ejecuta el tailer de logs en un thread separado."""
    tailer = LogTailer()

    while True:
        try:
            lines = tailer.read_new_lines()
            if lines:
                tailer.process_lines(lines)
        except Exception:
            pass  # Evitar que el thread muera por errores
        time.sleep(POLL_INTERVAL)


# =============================================================================
# APLICACIÓN FLASK
# =============================================================================

app = Flask(__name__)


# ── Ruta principal: HTML ──

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


# ── SSE: Tráfico ──

@app.route("/stream/traffic")
def stream_traffic():
    def generate():
        while True:
            try:
                event = traffic_queue.get(timeout=SSE_KEEPALIVE)
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
            except Empty:
                # Heartbeat para mantener la conexión viva
                yield f": heartbeat {timestamp()}\n\n"
    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── SSE: Alertas ──

@app.route("/stream/alerts")
def stream_alerts():
    def generate():
        while True:
            try:
                event = alert_queue.get(timeout=SSE_KEEPALIVE)
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
            except Empty:
                yield f": heartbeat {timestamp()}\n\n"
    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── API: Estadísticas (para la UI) ──

@app.route("/api/stats")
def api_stats():
    return jsonify({
        "total_queries": _stats["total_queries"],
        "honeytoken_hits": _stats["honeytoken_hits"],
        "revoked_users": _stats["revoked_users"],
        "revoked_users_list": sorted(_revoked_users),
    })


# =============================================================================
# HTML TEMPLATE (inline — single file)
# =============================================================================

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Dashboard — Honeylab</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg-primary: #070708;
    --bg-surface: #0d0d0f;
    --bg-card:   #111115;
    --border:    #1a1a1e;
    --text:      #e4e4e7;
    --text-dim:  #8e8e93;
    --accent:    #06b6d4;
    --emerald:   #10b981;
    --red:       #ef4444;
    --amber:     #f59e0b;
    --font-sans: 'Inter', -apple-system, sans-serif;
    --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
  }

  html          { font-size: 15px; }
  body {
    font-family: var(--font-sans);
    background: var(--bg-primary);
    color: var(--text);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }

  /* ── HEADER ── */
  header {
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border);
    padding: 0.75rem 1.5rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-shrink: 0;
  }
  .header-left  { display: flex; align-items: center; gap: 1rem; }
  .header-left h1 {
    font-size: 1.1rem;
    font-weight: 600;
    letter-spacing: -0.02em;
  }
  .header-left h1 span { color: var(--accent); }
  .status-badge {
    font-family: var(--font-mono);
    font-size: 0.7rem;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-weight: 600;
    letter-spacing: 0.05em;
  }
  .status-nominal  { background: rgba(16, 185, 129, 0.15); color: var(--emerald); border: 1px solid rgba(16, 185, 129, 0.3); }
  .status-alerta   { background: rgba(239, 68, 68, 0.15);  color: var(--red);    border: 1px solid rgba(239, 68, 68, 0.3); animation: pulse 1.5s ease-in-out infinite; }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50%      { opacity: 0.5; }
  }

  .header-stats {
    display: flex;
    gap: 1.5rem;
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--text-dim);
  }
  .header-stats strong { color: var(--text); font-weight: 500; }
  .header-stats .num-honey { color: var(--red); }

  /* ── MAIN LAYOUT (dos paneles) ── */
  main {
    display: grid;
    grid-template-columns: 1.5fr 1fr;
    gap: 1px;
    background: var(--border);
    flex: 1;
    min-height: 0;
  }
  .panel {
    background: var(--bg-primary);
    display: flex;
    flex-direction: column;
    min-height: 0;
    overflow: hidden;
  }
  .panel-header {
    padding: 0.75rem 1.25rem;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .panel-header h2 {
    font-size: 0.85rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .panel-header .count {
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--text-dim);
    background: var(--bg-card);
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
  }
  .panel-header .count-warn { color: var(--red); background: rgba(239,68,68,0.1); }

  .panel-body {
    flex: 1;
    overflow-y: auto;
    padding: 0.5rem;
    font-family: var(--font-mono);
    font-size: 0.75rem;
    line-height: 1.5;
  }
  .panel-body::-webkit-scrollbar { width: 4px; }
  .panel-body::-webkit-scrollbar-track { background: var(--bg-primary); }
  .panel-body::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  /* ── TRAFFIC ENTRIES ── */
  .entry {
    padding: 0.4rem 0.6rem;
    margin-bottom: 2px;
    border-radius: 4px;
    background: var(--bg-card);
    border-left: 3px solid var(--border);
    animation: fadeIn 0.3s ease-out;
  }
  .entry-normal   { border-left-color: var(--accent); }
  .entry-honeytoken { border-left-color: var(--red); background: rgba(239,68,68,0.08); }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(-4px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  .entry .meta {
    display: flex;
    gap: 0.75rem;
    font-size: 0.65rem;
    color: var(--text-dim);
    margin-bottom: 0.2rem;
  }
  .entry .meta .user { color: var(--accent); }
  .entry .meta .user-susp { color: var(--red); }

  .entry .sql {
    color: var(--text);
    word-break: break-all;
    white-space: pre-wrap;
  }
  .entry .sql .keyword { color: var(--accent); }
  .entry .sql .string { color: var(--emerald); }

  /* ── ALERT ENTRIES ── */
  .alert-entry {
    padding: 0.6rem;
    margin-bottom: 4px;
    border-radius: 6px;
    animation: alertSlide 0.4s ease-out;
  }
  @keyframes alertSlide {
    from { opacity: 0; transform: translateX(20px); }
    to   { opacity: 1; transform: translateX(0); }
  }

  .alert-intruso {
    background: rgba(239,68,68,0.12);
    border: 1px solid rgba(239,68,68,0.3);
  }
  .alert-contenido {
    background: rgba(16,185,129,0.12);
    border: 1px solid rgba(16,185,129,0.3);
  }
  .alert-info {
    background: rgba(6,182,212,0.08);
    border: 1px solid rgba(6,182,212,0.2);
  }

  .alert-entry .alert-icon  { font-size: 1rem; margin-right: 0.4rem; }
  .alert-entry .alert-title { font-weight: 600; font-size: 0.8rem; }
  .alert-entry .alert-time  { font-size: 0.65rem; color: var(--text-dim); }
  .alert-entry .alert-detail {
    margin-top: 0.3rem;
    font-size: 0.7rem;
    color: var(--text-dim);
    font-family: var(--font-mono);
  }
  .alert-entry .alert-detail strong { color: var(--text); }

  .alert-intruso .alert-title   { color: var(--red); }
  .alert-contenido .alert-title { color: var(--emerald); }
  .alert-info .alert-title      { color: var(--accent); }

  /* ── EMPTY STATE ── */
  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--text-dim);
    font-size: 0.8rem;
    text-align: center;
    gap: 0.5rem;
  }
  .empty-state .icon { font-size: 2rem; opacity: 0.3; }

  /* ── RESPONSIVE ── */
  @media (max-width: 768px) {
    main { grid-template-columns: 1fr; }
    header { flex-direction: column; gap: 0.5rem; align-items: flex-start; }
    .header-stats { flex-wrap: wrap; gap: 0.75rem; }
  }
</style>
</head>
<body>

<!-- ─── HEADER ─── -->
<header>
  <div class="header-left">
    <h1>🛡️ SOC <span>Honeylab</span></h1>
    <span class="status-badge status-nominal" id="statusBadge">● NOMINAL</span>
  </div>
  <div class="header-stats">
    <span>Consultas: <strong id="statTotal">0</strong></span>
    <span class="num-honey">Honeytoken: <strong id="statHoney">0</strong></span>
    <span>Aislados: <strong id="statRevoked">0</strong></span>
  </div>
</header>

<!-- ─── MAIN: DOS PANELES ─── -->
<main>
  <!-- PANEL IZQUIERDO: TRÁFICO -->
  <section class="panel" id="trafficPanel">
    <div class="panel-header">
      <h2>🖥️  Tráfico en directo</h2>
      <span class="count" id="trafficCount">0 eventos</span>
    </div>
    <div class="panel-body" id="trafficBody">
      <div class="empty-state" id="trafficEmpty">
        <div class="icon">📡</div>
        <div>Esperando consultas SQL…</div>
        <div style="font-size:0.7rem">Ejecutá traffic_simulator.py para generar tráfico</div>
      </div>
    </div>
  </section>

  <!-- PANEL DERECHO: ALERTAS Y RESPUESTA -->
  <section class="panel" id="alertsPanel">
    <div class="panel-header">
      <h2>🛡️  Alertas y Respuesta</h2>
      <span class="count" id="alertsCount">0 eventos</span>
    </div>
    <div class="panel-body" id="alertsBody">
      <div class="empty-state" id="alertsEmpty">
        <div class="icon">🔒</div>
        <div>Sistema segura — Sin intrusiones</div>
        <div style="font-size:0.7rem">Las alertas aparecerán aquí automáticamente</div>
      </div>
    </div>
  </section>
</main>

<!-- ─── JAVASCRIPT: SSE + UI ─── -->
<script>
(function() {
  'use strict';

  const trafficBody  = document.getElementById('trafficBody');
  const alertsBody   = document.getElementById('alertsBody');
  const trafficEmpty = document.getElementById('trafficEmpty');
  const alertsEmpty  = document.getElementById('alertsEmpty');
  const trafficCount = document.getElementById('trafficCount');
  const alertsCount  = document.getElementById('alertsCount');
  const statusBadge  = document.getElementById('statusBadge');
  const statTotal    = document.getElementById('statTotal');
  const statHoney    = document.getElementById('statHoney');
  const statRevoked  = document.getElementById('statRevoked');

  let trafficEvents  = 0;
  let alertEvents    = 0;

  // ── Auto-scroll (con detección de scroll manual) ──
  function autoScroll(el) {
    const threshold = 30;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < threshold;
    if (atBottom) {
      el.scrollTop = el.scrollHeight;
    }
  }

  // ── Generar snippet SQL con keywords coloreadas ──
  function highlightSQL(sql) {
    return sql
      .replace(/\b(SELECT|FROM|WHERE|JOIN|LEFT|RIGHT|INNER|OUTER|ON|AND|OR|NOT|IN|LIKE|ORDER|BY|GROUP|HAVING|LIMIT|OFFSET|AS|COUNT|SUM|AVG|MIN|MAX|ROUND|TO_CHAR|CASE|WHEN|THEN|ELSE|END|IS|NULL|TRUE|FALSE|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TABLE|INTO|VALUES|SET|DISTINCT|UNION|ALL|EXISTS|BETWEEN|ASC|DESC|CAST|COALESCE|REVOKE|GRANT|PRIVILEGES|SCHEMA|PUBLIC|ALL|FROM|TO)\b/gi, '<span class="keyword">$1</span>')
      .replace(/'[^']*'/g, match => `<span class="string">${match}</span>`);
  }

  // ── Añadir entrada de tráfico ──
  function addTrafficEntry(data) {
    trafficEvents++;
    trafficCount.textContent = trafficEvents + ' eventos';

    if (trafficEmpty && trafficEmpty.parentNode) {
      trafficEmpty.remove();
    }

    const div = document.createElement('div');
    const isHoney = data.type === 'honeytoken_traffic';
    div.className = `entry ${isHoney ? 'entry-honeytoken' : 'entry-normal'}`;

    const userClass = isHoney ? 'user-susp' : 'user';
    const userLabel = isHoney ? '⚠ ' : '';

    div.innerHTML = `
      <div class="meta">
        <span>${data.timestamp || ''}</span>
        <span class="${userClass}">${userLabel}${data.user || '?'}</span>
        <span>${data.ip || '?'}</span>
      </div>
      <div class="sql">${highlightSQL(data.query || '')}</div>
    `;

    trafficBody.appendChild(div);
    autoScroll(trafficBody);
  }

  // ── Añadir entrada de alerta ──
  function addAlertEntry(data) {
    alertEvents++;
    alertsCount.textContent = alertEvents + ' eventos';

    if (alertsEmpty && alertsEmpty.parentNode) {
      alertsEmpty.remove();
    }

    const div = document.createElement('div');

    // Cambiar badge de estado a alerta
    statusBadge.className = 'status-badge status-alerta';
    statusBadge.textContent = '● ALERTA';

    if (data.type === 'honeytoken') {
      // Alerta de intrusión
      div.className = 'alert-entry alert-intruso';
      div.innerHTML = `
        <div>
          <span class="alert-icon">🚨</span>
          <span class="alert-title">HONEYTOKEN ACCEDIDA</span>
          <span class="alert-time">${data.timestamp || ''}</span>
        </div>
        <div class="alert-detail">
          <strong>Usuario:</strong> ${data.user || '?'}<br>
          <strong>IP origen:</strong> ${data.ip || '?'}<br>
          <strong>Query:</strong> ${(data.query || '').substring(0, 120)}
        </div>
      `;

      // Después de la intrusión, añadir el resultado de la respuesta
      setTimeout(() => {
        const respDiv = document.createElement('div');
        if (data.revoked) {
          respDiv.className = 'alert-entry alert-contenido';
          respDiv.innerHTML = `
            <div>
              <span class="alert-icon">✅</span>
              <span class="alert-title">RESPUESTA ACTIVA — Amenaza contenida</span>
              <span class="alert-time">${data.timestamp || ''}</span>
            </div>
            <div class="alert-detail">
              <strong>Acción:</strong> REVOKE ALL PRIVILEGES ON ALL TABLES<br>
              <strong>Usuario:</strong> ${data.user || '?'}<br>
              <strong>Estado:</strong> AISLADO — el atacante perdió todo acceso
            </div>
          `;
        } else {
          respDiv.className = 'alert-entry alert-info';
          respDiv.innerHTML = `
            <div>
              <span class="alert-icon">⚠️</span>
              <span class="alert-title">RESPUESTA ACTIVA — Falló la revocación</span>
              <span class="alert-time">${data.timestamp || ''}</span>
            </div>
            <div class="alert-detail">
              <strong>Usuario:</strong> ${data.user || '?'}<br>
              <strong>Estado:</strong> No se pudo revocar privilegios. Revisar conexión admin.
            </div>
          `;
        }
        alertsBody.appendChild(respDiv);
        autoScroll(alertsBody);
      }, 300);

    } else {
      div.className = 'alert-entry alert-info';
      div.innerHTML = `
        <div>
          <span class="alert-icon">ℹ️</span>
          <span class="alert-title">${data.title || 'Evento SOAR'}</span>
          <span class="alert-time">${data.timestamp || ''}</span>
        </div>
        <div class="alert-detail">${data.message || JSON.stringify(data)}</div>
      `;
    }

    alertsBody.appendChild(div);
    autoScroll(alertsBody);

    // Actualizar estadísticas
    updateStats();
  }

  // ── Actualizar estadísticas desde API ──
  function updateStats() {
    fetch('/api/stats')
      .then(r => r.json())
      .then(s => {
        statTotal.textContent   = s.total_queries;
        statHoney.textContent   = s.honeytoken_hits;
        statRevoked.textContent = s.revoked_users;

        // Si hay usuario aislados, badge rojo
        if (s.revoked_users > 0) {
          statusBadge.className = 'status-badge status-alerta';
          statusBadge.textContent = '● AISLAMIENTO ACTIVO';
        }
      })
      .catch(() => {});
  }

  // ── SSE: Tráfico ──
  const trafficSource = new EventSource('/stream/traffic');
  trafficSource.onmessage = function(e) {
    try {
      const data = JSON.parse(e.data);
      addTrafficEntry(data);
    } catch (err) {
      // ignorar
    }
  };
  trafficSource.onerror = function() {
    console.warn('SSE traffic: conexión perdida. Reconectando…');
  };

  // ── SSE: Alertas ──
  const alertsSource = new EventSource('/stream/alerts');
  alertsSource.onmessage = function(e) {
    try {
      const data = JSON.parse(e.data);
      addAlertEntry(data);
    } catch (err) {
      // ignorar
    }
  };
  alertsSource.onerror = function() {
    console.warn('SSE alerts: conexión perdida. Reconectando…');
  };

  // ── Stats periódicos ──
  setInterval(updateStats, 5000);
  updateStats();

  console.log('📡 SOC Dashboard conectado.');
})();
</script>
</body>
</html>"""

# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    # ── Mostrar banner ──
    print(f"""
  {chr(27)}[36m╔══════════════════════════════════════════════════════════════╗
  ║  🛡️  SOC DASHBOARD — Honeylab Active Defense  🛡️        ║
  ║  Flask + SSE   |   Tiempo real  |   Respuesta activa    ║
  ╚══════════════════════════════════════════════════════════════╝{chr(27)}[0m
  """)
    print(f"  {chr(27)}[36mPuerto:{chr(27)}[0m       http://localhost:{FLASK_PORT}")
    print(f"  {chr(27)}[36mLogs:{chr(27)}[0m         {LOG_DIR.resolve()}")
    print(f"  {chr(27)}[36mCebo:{chr(27)}[0m          {HONEYTOKEN_TABLE}")
    print(f"  {chr(27)}[36mPolling:{chr(27)}[0m       cada {POLL_INTERVAL}s")
    print(f"\n  {chr(27)}[33mRecomendación:{chr(27)}[0m  Ejecutá traffic_simulator.py en otra terminal")
    print(f"  {chr(27)}[33mMonitor:{chr(27)}[0m         Abrí http://localhost:{FLASK_PORT} en tu navegador\n")

    # ── Iniciar thread de background ──
    reader_thread = threading.Thread(target=background_log_reader, daemon=True)
    reader_thread.start()

    # ── Iniciar Flask ──
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, threaded=True)
