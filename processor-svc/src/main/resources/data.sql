-- Seeding dispositivi
INSERT INTO device_registry (device_id, owner, model, fw_version, enabled, min_algo)
VALUES ('cnc-23', 'Reparto CNC', 'CNC-X200', '1.0.3', TRUE, 'AES-256-GCM+HMAC-SHA256')
ON CONFLICT (device_id) DO NOTHING;

-- Seeding chiavi
INSERT INTO key_material (key_id, algo, status)
VALUES ('k-2025-01', 'AES-256-GCM+HMAC-SHA256', 'ACTIVE')
ON CONFLICT (key_id) DO NOTHING;
