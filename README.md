# 🛡️ Honeylab — Deception Technology & Active Defense

<p align="center">
  <img src="https://img.shields.io/badge/PostgreSQL-16-316192?style=flat&logo=postgresql&logoColor=white">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=flat&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white">
  <img src="https://img.shields.io/badge/Flask-3.0-000000?style=flat&logo=flask&logoColor=white">
  <img src="https://img.shields.io/badge/MITRE-Shield%20DTE0012-000000?style=flat">
  <img src="https://img.shields.io/badge/Estado-Producci%C3%B3n%20Demo-10b981?style=flat">
</p>

<p align="center">
  <b>Laboratorio de Defensa Activa · Blue Team · Ciberseguridad Ofensiva-Defensiva</b><br>
  <i>Detección en tiempo real de accesos indebidos mediante Honeytokens PostgreSQL<br>
  con respuesta automática SOAR y dashboard web interactivo.</i>
</p>

---

## 📋 Tabla de contenidos

- [¿Qué es Deception Technology?](#-qué-es-deception-technology)
- [Impacto de negocio](#-impacto-de-negocio)
- [Arquitectura del laboratorio](#-arquitectura-del-laboratorio)
- [Inicio rápido](#-inicio-rápido)
- [Servicios](#-servicios)
- [Demo guiada](#-demo-guiada)
- [Lo que demuestra este laboratorio](#-lo-que-demuestra-este-laboratorio)
- [Estructura del proyecto](#-estructura-del-proyecto)
- [Créditos](#-créditos)

---

## 🎯 ¿Qué es Deception Technology?

**Deception Technology** es una estrategia de ciberseguridad ofensivo-defensiva que consiste en desplegar señuelos (honeytokens, honeypots) dentro de la infraestructura real de una organización para **detectar, alertar y responder automáticamente** ante accesos no autorizados.

A diferencia de los sistemas de detección tradicionales (que buscan patrones de ataque conocidos), el engaño activo **invierte la asimetría**: el atacante no sabe qué es real y qué es un señuelo. Cualquier interacción con un honeytoken es, por definición, una intrusión en curso.

### MITRE Shield DTE0012

Este laboratorio implementa la técnica **MITRE Shield DTE0012 — Honeytokens**, que se correlaciona con el ATT&CK T1078 (Valid Accounts). Cuando un atacante utiliza credenciales robadas para moverse lateralmente y encuentra una tabla de credenciales VPN, no sabe que está ante un señuelo. Y para cuando lo descubre, ya está aislado.

### Las tres capas de detección

| Capa | Mecanismo | Latencia | Propósito |
|------|-----------|----------|-----------|
| **1. Tiempo real** | `pg_notify` + LISTEN | < 1 s | Alerta inmediata al SOC |
| **2. Persistencia SQL** | Trigger → `tb_audit_log` | < 1 s | Registro forense consultable |
| **3. Log parsing** | Ficheros PostgreSQL | ~ 1 s | Correlación y backup |

---

## 💼 Impacto de negocio

> **"El tiempo medio de detección de una intrusión (MTTD) se reduce de días a segundos. El tiempo medio de respuesta (MTTR) pasa de horas a milisegundos."**

### ¿Qué pasaría en un entorno real?

1. **Un atacante obtiene credenciales** de un empleado mediante phishing o fuerza bruta.
2. **Escanea la base de datos** en busca de información valiosa.
3. **Encuentra `tb_credenciales_vpn_admin`** — un nombre que promete acceso a la VPN corporativa.
4. **Ejecuta `SELECT * FROM tb_credenciales_vpn_admin`** — y en ese mismo instante:
   - ✅ El SOC recibe una alerta con el usuario, IP y consulta exacta.
   - ✅ El sistema **revoca automáticamente todos los permisos** del atacante.
   - ✅ La exfiltración de datos se ha **prevenido en tiempo real**.

### Métricas del laboratorio

| Indicador | Valor |
|-----------|-------|
| Tiempo de detección | < 1 s (NOTIFY) |
| Tiempo de respuesta | < 2 s (REVOKE automático) |
| Falsos positivos | 0% (solo accesos a la honeytoken disparan alertas) |
| Cobertura MITRE ATT&CK | T1078, T1003, T1049 |

---

## 🏗️ Arquitectura del laboratorio

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           DOCKER COMPOSE                                │
│                                                                         │
│  ┌──────────────────────┐    ┌──────────────────────┐                  │
│  │   PostgreSQL 16       │    │   Python 3.12-slim   │                  │
│  │   (postgres_honeylab) │    │   (traffic_simulator) │                  │
│  │                       │    │                       │                  │
│  │  ┌─────────────────┐  │    │  95% consultas       │                  │
│  │  │ tb_clientes     │  │    │  normales            │                  │
│  │  │ tb_facturacion  │  │◄───│                      │                  │
│  │  └─────────────────┘  │    │  5% honeytoken       │                  │
│  │  ┌─────────────────┐  │    │                      │                  │
│  │  │ tb_credenciales_│  │◄───│                      │                  │
│  │  │ vpn_admin (CEBO)│  │    └──────────────────────┘                  │
│  │  └─────────────────┘  │                                              │
│  │  ┌─────────────────┐  │    ┌──────────────────────┐                  │
│  │  │ tb_audit_log    │  │    │   Python 3.12-slim   │                  │
│  │  └─────────────────┘  │    │   (dashboard_soc)    │                  │
│  │                       │    │                       │                  │
│  │  logs/ ──volumen──►   │◄───│  Tail logs + NOTIFY  │                  │
│  │                       │    │  + REVOKE automático  │                  │
│  └──────────────────────┘    │                       │                  │
│                               │  Web: localhost:5001  │                  │
│                               └──────────────────────┘                  │
│                                   ┌──────────────────────┐              │
│                                   │   Navegador          │              │
│                                   │   ┌─────────────┐   │              │
│                                   │   │ Tráfico SQL  │   │              │
│                                   │   │ (SSE实时)    │   │              │
│                                   │   ├─────────────┤   │              │
│                                   │   │ Alertas SOAR │   │              │
│                                   │   │ (SSE实时)    │   │              │
│                                   │   └─────────────┘   │              │
│                                   └──────────────────────┘              │
└─────────────────────────────────────────────────────────────────────────┘
```

### Flujo de detección y respuesta activa

```
1. empleado_sospechoso → SELECT * FROM tb_credenciales_vpn_admin
                              │
                              ▼
2. PostgreSQL log  ────►  dashboard_soc.py (LogTailer)
                              │
                              ├── Regex: ¿HONEYTOKEN_TABLE en query?
                              │       └── Sí → ALERTA CRÍTICA
                              │
                              ├── ¿Usuario exento? (postgres)
                              │       └── No → RESPUESTA ACTIVA
                              │
                              └── Conexión admin → REVOKE ALL PRIVILEGES
                                      ON ALL TABLES IN SCHEMA public
                                      FROM empleado_sospechoso
                                      │
                                      ▼
                              Usuario AISLADO — cualquier SELECT
                              posterior devuelve "permission denied"
```

---

## ⚡ Inicio rápido

### Requisitos

- **Docker** >= 24
- **Docker Compose** >= 2.20
- **Git** (opcional, para clonar)
- 2 GB de RAM disponibles

### 1. Clonar y levantar

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/honeylab.git
cd honeylab

# Construir imágenes y levantar servicios
docker compose up -d --build
```

### 2. Abrir el dashboard

```
http://localhost:5001
```

Verás el SOC Dashboard con dos paneles vacíos esperando tráfico.

### 3. El laboratorio ya está en marcha

El `traffic_simulator` se inicia automáticamente y empieza a generar tráfico:

- **Cada 1.5–5 segundos** ejecuta una consulta SQL.
- **95 %** de las veces como `empleado_normal` con consultas legítimas.
- **5 %** de las veces como `empleado_sospechoso` accediendo a la honeytoken.

No necesitas hacer nada más. Las alertas aparecerán solas en el dashboard.

### 4. Verificar que todo funciona

```bash
# Estado de los servicios
docker compose ps

# Logs del tráfico
docker compose logs -f traffic_simulator

# Logs del dashboard
docker compose logs -f dashboard_soc
```

### Comandos útiles

| Comando | Qué hace |
|---------|----------|
| `docker compose up -d --build` | Construye y levanta todo |
| `docker compose ps` | Muestra estado de los servicios |
| `docker compose logs -f dashboard_soc` | Logs del dashboard en vivo |
| `docker compose logs -f traffic_simulator` | Logs del simulador de tráfico |
| `docker compose stop` | Detiene servicios (preserva datos) |
| `docker compose down -v` | Destruye todo (borra datos y logs) |

---

## 🖥️ Servicios

### 1. PostgreSQL 16 (`postgres_honeylab`)

Base de datos con auditoría completa y honeytokens embebidos.

- **Puerto expuesto:** `5433` (para conexiones externas)
- **Logs:** `log_statement=all`, `log_connections=on`, `log_line_prefix` con usuario, IP y query
- **Salud:** Healthcheck cada 10 segundos

#### Credenciales

| Rol | Usuario | Contraseña | Permisos |
|-----|---------|-----------|----------|
| Superadmin | `postgres` | `SuperAdmin_Lab_2024!` | Todo |
| Empleado normal | `empleado_normal` | `P@ssw0rd_Normal_2024!` | SELECT tablas legítimas |
| Empleado sospechoso | `empleado_sospechoso` | `P@ssw0rd_Sospech_2024!` | SELECT tablas legítimas + cebo |

### 2. Simulador de tráfico (`traffic_simulator`)

Genera actividad SQL realista en bucle infinito para que el dashboard tenga contenido en vivo.

- **20 consultas distintas** en su repertorio: SELECTs simples, JOINs, agregaciones, GROUP BY, LEFT JOINs.
- **Distribución 95/5:** el 5 % de las queries activa la honeytoken.
- **Pausas aleatorias:** entre 1.5 y 5 segundos para simular comportamiento humano.

### 3. Dashboard SOC (`dashboard_soc`)

Aplicación web Flask con **Server-Sent Events (SSE)** que funciona como:

- **Monitor de tráfico:** muestra cada consulta SQL en el panel izquierdo con syntax highlighting.
- **SOAR Active Defense:** detecta accesos a la honeytoken en los logs y ejecuta `REVOKE ALL PRIVILEGES` automáticamente.
- **Panel de alertas:** panel derecho con historial de intrusiones y respuestas.

#### Funcionalidades clave

| Característica | Implementación |
|----------------|---------------|
| Actualización en tiempo real | SSE (2 canales independientes) |
| Sin recarga de página | EventSource nativo del navegador |
| Scroll inteligente | Auto-scroll solo si el usuario está al final |
| Syntax highlighting SQL | Regex en JavaScript para keywords + strings |
| Badge de estado | NOMINAL → ALERTA → AISLAMIENTO ACTIVO |
| Heartbeats SSE | Cada 15 segundos para mantener conexión |
| Persistencia de logs | Volumen Docker compartido |

---

## 🎬 Demo guiada

### Paso 1: Todo funcionando

```bash
docker compose up -d --build
```

Espera 10 segundos a que PostgreSQL termine la inicialización y el healthcheck pase.

### Paso 2: Abrir el dashboard

```
http://localhost:5001
```

### Paso 3: Observar el tráfico normal

En el panel izquierdo verás consultas como:

```
[14:30:01] empleado_normal
  SELECT * FROM tb_clientes LIMIT 5;

[14:30:03] empleado_normal
  SELECT estado, COUNT(*) AS cantidad, SUM(importe_total)
  FROM tb_facturacion
  GROUP BY estado;

[14:30:06] empleado_normal
  SELECT c.nombre, c.apellidos, SUM(f.importe_total) AS gasto_total
  FROM tb_clientes c
  JOIN tb_facturacion f ON f.cliente_id = c.id
  GROUP BY c.id, c.nombre, c.apellidos
  ORDER BY gasto_total DESC
  LIMIT 5;
```

### Paso 4: Ver la intrusión

Cuando el `empleado_sospechoso` caiga en la trampa:

**Panel izquierdo** — la query aparece marcada en rojo:

```
[14:32:15] ⚠ empleado_sospechoso
  SELECT * FROM tb_credenciales_vpn_admin;
```

**Panel derecho** — aparecen dos eventos secuenciales:

```
🚨 HONEYTOKEN ACCEDIDA
   Usuario: empleado_sospechoso
   IP: 172.17.0.1
   Query: SELECT * FROM tb_credenciales_vpn_admin

✅ RESPUESTA ACTIVA — Amenaza contenida
   Acción: REVOKE ALL PRIVILEGES ON ALL TABLES
   Usuario: empleado_sospechoso
   Estado: AISLADO — el atacante perdió todo acceso
```

El badge de estado en el header cambia a **ALERTA** con animación pulse.

### Paso 5: Confirmar el aislamiento

Si el `empleado_sospechoso` intenta cualquier SELECT después del REVOKE:

```sql
SELECT * FROM tb_clientes;
ERROR:  permission denied for table tb_clientes
```

El atacante está **completamente aislado** sin necesidad de intervención humana.

---

## 🧠 Lo que demuestra este laboratorio

### Habilidades técnicas

| Tecnología | Lo que se demuestra |
|------------|---------------------|
| **PostgreSQL** | Creación de roles, tablas, triggers, funciones, NOTIFY, auditoría, log_statement=all |
| **Docker** | Multi-contenedor, volúmenes compartidos, healthchecks, redes internas |
| **Python** | Expresiones regulares, threading, colas, parseo de logs, conexiones BD |
| **Flask** | SSE (Server-Sent Events), streaming responses, APIs REST |
| **SOAR** | Detección automatizada + respuesta activa (REVOKE) en tiempo real |
| **Regex** | Parseo de log_line_prefix de PostgreSQL, detección de patrones SQL |
| **Ciberseguridad** | Deception Technology, MITRE Shield DTE0012, Honeytokens, aislamiento de atacantes |

### Habilidades blandas

- **Arquitectura de defensa:** Diseño de un sistema de detección multicapa.
- **Automatización:** Reducción del MTTR de horas a milisegundos.
- **Documentación técnica:** Este mismo README.
- **Visión de negocio:** Comprensión del impacto de la exfiltración de datos y cómo prevenirla.

### Stack tecnológico

```
🐘 PostgreSQL 16      → Base de datos con auditoría y triggers
🐍 Python 3.12        → Lógica de detección, respuesta y web
🐳 Docker Compose     → Orquestación de 3 contenedores
🌐 Flask 3.0          → Dashboard web con SSE en tiempo real
🔌 psycopg2           → Conexión nativa a PostgreSQL
🎨 colorama           → Output coloreado en terminal
```

---

## 📁 Estructura del proyecto

```
honeylab/
│
├── docker-compose.yml            # Orquestación: BD + tráfico + dashboard
├── Dockerfile                    # Imagen Python 3.12-slim optimizada
├── requirements.txt              # Dependencias Python
├── init.sql                      # Schema, datos, honeytoken, triggers, roles
├── postgresql.conf               # Auditoría completa de PostgreSQL
│
├── dashboard_soc.py              # ★ Web Flask + SSE + SOAR Active Defense
├── traffic_simulator.py          # Generador de tráfico SQL (95/5)
├── soc_active_defense.py         # SOAR en terminal (alternativo)
├── monitor_honeylab.py           # Monitor de consola (alternativo)
│
├── logs/                         # Logs de PostgreSQL (volumen compartido)
└── README.md                     # Esta documentación
```

---

## 🧪 Ejecución local (sin Docker)

Si preferís ejecutar los scripts en tu máquina directamente:

```bash
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. Levantar solo PostgreSQL
docker compose up -d postgres_honeylab

# 3. En terminales separadas:
python traffic_simulator.py
python dashboard_soc.py

# Opcional:
python monitor_honeylab.py
python soc_active_defense.py
```

---

## 🔒 Consideraciones de seguridad

> **Este laboratorio es exclusivamente educativo.** Las credenciales y datos aquí contenidos son ficticios y no deben utilizarse en entornos reales.

- La contraseña del superadmin (`SuperAdmin_Lab_2024!`) es débil deliberadamente para facilitar el laboratorio.
- La clave RSA privada en la honeytoken es ficticia y generada para el ejemplo.
- Los datos de clientes y facturación son completamente inventados.

Para un despliegue real:
- Utilizar un gestor de secretos (Vault, AWS Secrets Manager).
- Habilitar SSL/TLS en las conexiones a PostgreSQL.
- Implementar autenticación multifactor.
- Rotar las contraseñas del laboratorio.

---

## 📚 Referencias

- [MITRE Shield — DTE0012: Honeytokens](https://shield.mitre.org/techniques/DTE0012/)
- [MITRE ATT&CK — T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [PostgreSQL Documentation — Logging](https://www.postgresql.org/docs/16/runtime-config-logging.html)
- [PostgreSQL Documentation — NOTIFY](https://www.postgresql.org/docs/16/sql-notify.html)
- [Flask SSE Patterns](https://flask.palletsprojects.com/en/3.0.x/patterns/streaming/)

---

## 📄 Licencia

Este proyecto es de uso educativo y está publicado bajo licencia MIT.

---

<p align="center">
  <b>Hecho con ☕ y 🐘 por un ingeniero de Blue Team</b><br>
  <i>"The best defense is active defense. Don't wait for the breach — bait it."</i>
</p>
