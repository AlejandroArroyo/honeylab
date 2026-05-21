-- =============================================================================
-- LABORATORIO: HONEYTOKENS & DEFENSA ACTIVA
-- Arquitectura Blue Team | Auditoría SQL + Cebo de Credenciales
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. USUARIOS: empleado_normal y empleado_sospechoso
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'empleado_normal') THEN
        CREATE ROLE empleado_normal LOGIN PASSWORD 'P@ssw0rd_Normal_2024!';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'empleado_sospechoso') THEN
        CREATE ROLE empleado_sospechoso LOGIN PASSWORD 'P@ssw0rd_Sospech_2024!';
    END IF;
END
$$;

-- -----------------------------------------------------------------------------
-- 2. ESQUEMA Y TABLAS LEGÍTIMAS DE NEGOCIO
-- -----------------------------------------------------------------------------

-- Tabla de clientes (legítima)
CREATE TABLE IF NOT EXISTS tb_clientes (
    id              SERIAL PRIMARY KEY,
    nombre          VARCHAR(100) NOT NULL,
    apellidos       VARCHAR(100),
    email           VARCHAR(150) UNIQUE NOT NULL,
    telefono        VARCHAR(20),
    nif             VARCHAR(15) UNIQUE,
    fecha_alta      DATE DEFAULT CURRENT_DATE,
    segmento        VARCHAR(30) CHECK (segmento IN ('PREMIUM','ESTANDAR','BASICO')),
    activo          BOOLEAN DEFAULT TRUE
);

-- Tabla de facturación (legítima)
CREATE TABLE IF NOT EXISTS tb_facturacion (
    id              SERIAL PRIMARY KEY,
    cliente_id      INT REFERENCES tb_clientes(id),
    numero_factura  VARCHAR(20) UNIQUE NOT NULL,
    fecha_emision   DATE NOT NULL,
    concepto        VARCHAR(255),
    importe_neto    NUMERIC(10,2),
    iva_pct         NUMERIC(4,2) DEFAULT 21.00,
    importe_total   NUMERIC(10,2) GENERATED ALWAYS AS (importe_neto * (1 + iva_pct/100)) STORED,
    estado          VARCHAR(20) CHECK (estado IN ('PAGADA','PENDIENTE','VENCIDA','ANULADA'))
);

-- -----------------------------------------------------------------------------
-- 3. DATOS FICTICIOS EN TABLAS LEGÍTIMAS
-- -----------------------------------------------------------------------------
INSERT INTO tb_clientes (nombre, apellidos, email, telefono, nif, segmento) VALUES
    ('Lucía',    'García Fernández',    'lucia.garcia@correo.es',      '+34 612 001 001', '12345678A', 'PREMIUM'),
    ('Marcos',   'López Ruiz',          'marcos.lopez@empresa.com',    '+34 612 002 002', '23456789B', 'PREMIUM'),
    ('Sara',     'Martínez Díaz',       'sara.martinez@mail.es',       '+34 612 003 003', '34567890C', 'ESTANDAR'),
    ('Andrés',   'Sánchez Moreno',      'andres.sanchez@web.org',      '+34 612 004 004', '45678901D', 'ESTANDAR'),
    ('Elena',    'Jiménez Álvarez',     'elena.jimenez@correo.es',     '+34 612 005 005', '56789012E', 'BASICO'),
    ('Pablo',    'Romero Torres',       'pablo.romero@empresa.com',    '+34 612 006 006', '67890123F', 'BASICO'),
    ('Carmen',   'Alonso Navarro',      'carmen.alonso@mail.es',       '+34 612 007 007', '78901234G', 'PREMIUM'),
    ('Javier',   'Gutiérrez Ramos',     'javier.gutierrez@web.org',    '+34 612 008 008', '89012345H', 'ESTANDAR')
ON CONFLICT DO NOTHING;

INSERT INTO tb_facturacion (cliente_id, numero_factura, fecha_emision, concepto, importe_neto, estado) VALUES
    (1, 'FAC-2024-0001', '2024-01-15', 'Servicio consultoría Q1',      4500.00, 'PAGADA'),
    (1, 'FAC-2024-0012', '2024-04-01', 'Servicio consultoría Q2',      4500.00, 'PAGADA'),
    (2, 'FAC-2024-0023', '2024-02-20', 'Licencia software anual',      1200.00, 'PAGADA'),
    (3, 'FAC-2024-0034', '2024-03-10', 'Soporte técnico mensual',       350.00, 'PAGADA'),
    (4, 'FAC-2024-0045', '2024-03-28', 'Mantenimiento infraestructura', 780.00, 'PENDIENTE'),
    (5, 'FAC-2024-0056', '2024-04-05', 'Formación corporativa',         600.00, 'PENDIENTE'),
    (6, 'FAC-2024-0067', '2024-01-30', 'Auditoría de sistemas',        2200.00, 'VENCIDA'),
    (7, 'FAC-2024-0078', '2024-05-12', 'Desarrollo a medida',          8900.00, 'PAGADA'),
    (8, 'FAC-2024-0089', '2024-05-20', 'Hosting y CPD mensual',         450.00, 'PENDIENTE')
ON CONFLICT DO NOTHING;

-- -----------------------------------------------------------------------------
-- 4. TABLA HONEYTOKEN — EL CEBO
--    Nombre diseñado para ser irresistible a un intruso:
--    credenciales de VPN del administrador
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tb_credenciales_vpn_admin (
    id              SERIAL PRIMARY KEY,
    descripcion     VARCHAR(200),
    host_vpn        VARCHAR(100),
    puerto          INT,
    usuario         VARCHAR(100),
    password_hash   TEXT,
    clave_privada   TEXT,
    otp_seed        VARCHAR(100),
    entorno         VARCHAR(30),
    ultima_rotacion DATE,
    notas           TEXT
);

-- Credenciales falsas diseñadas para parecer auténticas
INSERT INTO tb_credenciales_vpn_admin
    (descripcion, host_vpn, puerto, usuario, password_hash, clave_privada, otp_seed, entorno, ultima_rotacion, notas)
VALUES
    (
        'Acceso VPN Administrador Principal - PRODUCCION',
        'vpn.corp-interna.local',
        1194,
        'admin_vpn_root',
        '$2b$12$K8zRpQ3mN7vLxWjY2cFt4OeHsDgIuVbCnXaElMwTqZy6PrA1hBk9.',
        '-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5RJr9vXMSBJQANpMdBDDIMGiUHDkIZtoy
TgH7N1Pk9Dz0jZzwQkQCmZfLSXh3hg3pGm0S8xyXyMXs2N8M0GQClRpNRBSAjn1
-----END RSA PRIVATE KEY-----',
        'JBSWY3DPEHPK3PXP',
        'PRODUCCION',
        '2024-03-01',
        'ROTAR cada 90 días. Contactar a sysadmin@corp-interna.local'
    ),
    (
        'Acceso VPN Backup - Administrador DR',
        'vpn-dr.corp-interna.local',
        1194,
        'dr_admin_backup',
        '$2b$12$Xv7nLqM4pR8sKwA2bEcT6OfGhJiUyDlCmZeNaVtBk3Ps1WxYgQ9.',
        '-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1z3tswplCQLzIPZf6SKr8wYNTCJRAOpNeBEEJNHiVHEkKatpz
UiI8O4 2Rm0TgA4jZywRmRDDoZhMLYViJEsJAHb2PmC0e0rCbzxUyNXs3P9N1GRC
-----END RSA PRIVATE KEY-----',
        'KVKFKRCPNBWKY3ZO',
        'DR-BACKUP',
        '2024-02-15',
        'Solo usar en caso de fallo del sistema primario. PIN: ver sobre sellado en caja fuerte B-3'
    )
ON CONFLICT DO NOTHING;

-- -----------------------------------------------------------------------------
-- 5. PERMISOS — solo lectura sobre tablas legítimas
-- IMPORTANTE: los usuarios tienen acceso a la honeytoken intencionalmente
--    para que el log de PostgreSQL (log_statement=all) registre el acceso
--    y los scripts Python puedan detectarlo y ejecutar la respuesta activa
-- -----------------------------------------------------------------------------
GRANT CONNECT ON DATABASE honeylab TO empleado_normal, empleado_sospechoso;
GRANT USAGE ON SCHEMA public TO empleado_normal, empleado_sospechoso;

-- Acceso legítimo
GRANT SELECT ON tb_clientes    TO empleado_normal, empleado_sospechoso;
GRANT SELECT ON tb_facturacion TO empleado_normal, empleado_sospechoso;

-- Acceso al cebo (SELECT permitido para que el intruso pueda activar el honeytoken)
-- En un entorno real, el acceso sería detectado vía log, SIEM o trigger NOTIFY
GRANT SELECT ON tb_credenciales_vpn_admin TO empleado_normal, empleado_sospechoso;

-- Sin escritura en ninguna tabla
REVOKE INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public FROM empleado_normal, empleado_sospechoso;

-- -----------------------------------------------------------------------------
-- 6. SISTEMA DE DETECCIÓN — LOG DE AUDITORÍA
--    PostgreSQL no permite triggers AFTER SELECT en tablas.
--    La detección de accesos a la honeytoken se realiza mediante:
--       a) log_statement=all en postgresql.conf → cada SELECT se registra
--       b) Los scripts Python (dashboard_soc.py, soc_active_defense.py,
--          monitor_honeylab.py) parsean los logs en tiempo real
--       c) Al detectar tb_credenciales_vpn_admin en una query, ejecutan
--          la respuesta activa (REVOKE ALL PRIVILEGES)
-- -----------------------------------------------------------------------------

-- Tabla de auditoría interna (para consulta manual por el superusuario)
CREATE TABLE IF NOT EXISTS tb_audit_log (
    id          SERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ DEFAULT NOW(),
    evento      VARCHAR(100),
    usuario_pg  VARCHAR(100),
    ip_origen   INET,
    puerto      INT,
    query_text  TEXT,
    tabla       VARCHAR(100)
);

-- Solo el superusuario puede leer la tabla de auditoría
REVOKE ALL ON tb_audit_log FROM empleado_normal, empleado_sospechoso;

-- -----------------------------------------------------------------------------
-- 7. VERIFICACIÓN FINAL
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    RAISE NOTICE '====================================================';
    RAISE NOTICE ' HONEYLAB inicializado correctamente';
    RAISE NOTICE ' Tablas legítimas : tb_clientes, tb_facturacion';
    RAISE NOTICE ' Honeytoken activa: tb_credenciales_vpn_admin';
    RAISE NOTICE ' Detección       : log_statement=all (log parsing)';
    RAISE NOTICE ' Respuesta activa: REVOKE automático via Python SOAR';
    RAISE NOTICE '====================================================';
END;
$$;
