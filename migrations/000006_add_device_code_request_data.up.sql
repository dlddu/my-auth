-- 000006_add_device_code_request_data.up.sql
-- Add request_data column to device_codes table to store the full serialized
-- fosite.Requester as JSON, consistent with other token tables.

ALTER TABLE device_codes ADD COLUMN request_data TEXT NOT NULL DEFAULT '{}';
