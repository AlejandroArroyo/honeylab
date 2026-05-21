# =============================================================================
# Dockerfile — Laboratorio Honeytokens & Defensa Activa
# Base optimizada: python:3.12-slim (~120 MB)
# =============================================================================
# Uso:
#   docker build -t honeylab-python .
#   docker run --rm honeylab-python python traffic_simulator.py
# =============================================================================

FROM python:3.12-slim

# ── Evitar que Python genere .pyc y forzar salida sin buffer ──
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# ── Directorio de trabajo ──
WORKDIR /app

# ── Copiar e instalar dependencias (cache layer) ──
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Crear directorio de logs (se montará como volumen) ──
RUN mkdir -p /app/logs

# ── Copiar scripts Python ──
COPY monitor_honeylab.py      .
COPY traffic_simulator.py     .
COPY soc_active_defense.py    .
COPY dashboard_soc.py         .

# ── Puerto del dashboard web ──
EXPOSE 5001

# ── Comando por defecto (se sobrescribe en docker-compose) ──
CMD ["python", "dashboard_soc.py"]
