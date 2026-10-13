-- =============================================================================
--  PoC Zero Trust para LLMs — Esquema de base de datos (PostgreSQL)
-- =============================================================================
--  Se crean 3 tablas IDÉNTICAS (misma estructura y mismos datos iniciales).
--  Cada una corresponde a un escenario de seguridad de la demo, así se puede
--  comparar lado a lado qué le pasa a los datos en cada caso:
--
--    reservas_sin_proteccion -> Guardrails OFF + Zero Trust OFF  (el ataque borra todo)
--    reservas_guardrails     -> Guardrails ON  + Zero Trust OFF  (capa 1 sola)
--    reservas_zero_trust     -> Zero Trust ON  (con o sin Guardrails)
--
--  Ejecutar con:  psql -h <host> -U <usuario> -d <base> -f schema.sql
--  ATENCIÓN: hace DROP de las tablas si ya existen (deja el estado inicial).
--  Si se cambian los datos semilla, actualizar también SEED_RESERVAS en app.py.
-- =============================================================================

DROP TABLE IF EXISTS reservas_sin_proteccion;
DROP TABLE IF EXISTS reservas_guardrails;
DROP TABLE IF EXISTS reservas_zero_trust;

CREATE TABLE reservas_sin_proteccion (
    id         SERIAL PRIMARY KEY,
    cliente    VARCHAR(120) NOT NULL,
    fecha      DATE         NOT NULL,
    estado     VARCHAR(20)  NOT NULL DEFAULT 'confirmada',
    creado_en  TIMESTAMP    NOT NULL DEFAULT now()
);

CREATE TABLE reservas_guardrails (
    id         SERIAL PRIMARY KEY,
    cliente    VARCHAR(120) NOT NULL,
    fecha      DATE         NOT NULL,
    estado     VARCHAR(20)  NOT NULL DEFAULT 'confirmada',
    creado_en  TIMESTAMP    NOT NULL DEFAULT now()
);

CREATE TABLE reservas_zero_trust (
    id         SERIAL PRIMARY KEY,
    cliente    VARCHAR(120) NOT NULL,
    fecha      DATE         NOT NULL,
    estado     VARCHAR(20)  NOT NULL DEFAULT 'confirmada',
    creado_en  TIMESTAMP    NOT NULL DEFAULT now()
);

-- Datos semilla (los mismos en las 3 tablas)
INSERT INTO reservas_sin_proteccion (cliente, fecha, estado) VALUES
    ('María González',   '2026-10-16', 'confirmada'),
    ('Juan Pérez',       '2026-10-17', 'confirmada'),
    ('Lucía Fernández',  '2026-10-18', 'pendiente'),
    ('Carlos Rodríguez', '2026-10-23', 'confirmada'),
    ('Sofía Martínez',   '2026-10-24', 'confirmada'),
    ('Diego López',      '2026-10-30', 'pendiente');

INSERT INTO reservas_guardrails (cliente, fecha, estado)
    SELECT cliente, fecha, estado FROM reservas_sin_proteccion ORDER BY id;
INSERT INTO reservas_zero_trust (cliente, fecha, estado)
    SELECT cliente, fecha, estado FROM reservas_sin_proteccion ORDER BY id;
