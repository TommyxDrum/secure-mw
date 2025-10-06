-- ============================================================
-- V1__init.sql
-- Inizializzazione schema database per Secure Middleware
-- ============================================================

-- Estensioni necessarie
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- 1) RAW MESSAGES
-- Memorizza i messaggi esattamente come ricevuti dal broker
-- (payload cifrato, metadati, firma) per audit e replay
-- ============================================================

CREATE TABLE IF NOT EXISTS messages_raw (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    topic            TEXT NOT NULL,
    kafka_partition  INT NOT NULL,
    kafka_offset     BIGINT NOT NULL,
    received_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    meta             JSONB NOT NULL,     -- deviceId, traceId, ts, schema, nonce...
    security         JSONB NOT NULL,     -- iv, sig, alg...
    ciphertext_b64   TEXT NOT NULL,
    headers          JSONB,

    UNIQUE(topic, kafka_partition, kafka_offset)
);

CREATE INDEX IF NOT EXISTS idx_messages_raw_received_at 
    ON messages_raw(received_at);

CREATE INDEX IF NOT EXISTS idx_messages_raw_meta_gin 
    ON messages_raw USING GIN(meta);

-- ============================================================
-- 2) DECODED MESSAGES
-- Memorizza i messaggi dopo verifica e decifratura
-- ============================================================

CREATE TABLE IF NOT EXISTS messages_decoded (
    id              UUID PRIMARY KEY,   -- stesso id del raw
    device_id       TEXT NOT NULL,
    event_ts        TIMESTAMPTZ NOT NULL,
    processed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    meta            JSONB NOT NULL,
    payload         JSONB NOT NULL,
    integrity_ok    BOOLEAN NOT NULL,
    auth_ok         BOOLEAN NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_decoded_device_ts 
    ON messages_decoded(device_id, event_ts);

CREATE INDEX IF NOT EXISTS idx_messages_decoded_payload_gin 
    ON messages_decoded USING GIN(payload);

-- ============================================================
-- 3) PROCESSING ERRORS
-- Traccia gli errori avvenuti durante verify/decrypt/persist
-- ============================================================

CREATE TABLE IF NOT EXISTS processing_errors (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    raw_id          UUID NOT NULL REFERENCES messages_raw(id) ON DELETE CASCADE,
    stage           TEXT NOT NULL,  -- VERIFY | DECRYPT | PERSIST
    error_code      TEXT,
    error_msg       TEXT,
    error_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    dlq_topic       TEXT,
    attempts        INT DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_processing_errors_stage 
    ON processing_errors(stage);

CREATE INDEX IF NOT EXISTS idx_processing_errors_error_at 
    ON processing_errors(error_at);

-- ============================================================
-- 4) DEVICE REGISTRY
-- Registro dei dispositivi/endpoint autorizzati (facoltativo)
-- ============================================================

CREATE TABLE IF NOT EXISTS device_registry (
    device_id       TEXT PRIMARY KEY,
    owner           TEXT,
    model           TEXT,
    fw_version      TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    min_algo        TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- 5) KEY MATERIAL METADATA
-- Metadati sulle chiavi crittografiche (no chiavi reali!)
-- ============================================================

CREATE TABLE IF NOT EXISTS key_material (
    key_id          TEXT PRIMARY KEY,
    algo            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at      TIMESTAMPTZ,
    status          TEXT NOT NULL CHECK (status IN ('ACTIVE', 'RETIRED'))
);

CREATE INDEX IF NOT EXISTS idx_key_material_status 
    ON key_material(status);

-- ============================================================
-- ✅ Fine script
-- ============================================================
