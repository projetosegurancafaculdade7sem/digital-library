-- Proteção contra reutilização de códigos TOTP (replay).
-- Aplicar ANTES de publicar a versão que usa a coluna (ddl-auto=validate falha sem ela):
--   psql "$SPRING_DATASOURCE_URL" -v ON_ERROR_STOP=1 -f docs/sql/totp-replay.sql
-- Idempotente: pode ser executado mais de uma vez.

ALTER TABLE tb_users ADD COLUMN IF NOT EXISTS totp_last_used_step BIGINT;
