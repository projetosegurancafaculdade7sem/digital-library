-- Endurecimento da cadeia de auditoria no PostgreSQL/Supabase.
-- Aplicar com: psql "$SPRING_DATASOURCE_URL" -v ON_ERROR_STOP=1 -f docs/sql/audit-hardening.sql
-- A aplicação continua usando ddl-auto=validate; este script trata restrições que o JPA não Garante.

BEGIN;

-- 1. Sequência monotônica sem duplicatas ou lacunas -------------------------
CREATE UNIQUE INDEX IF NOT EXISTS uk_audit_sequence
    ON security_audit_logs (sequence_no);

CREATE OR REPLACE FUNCTION fn_audit_sequence_guard() RETURNS trigger AS $$
DECLARE
    expected bigint;
BEGIN
    -- Serializa a atribuição de sequência mesmo se houver mais de uma instância da aplicação.
    PERFORM pg_advisory_xact_lock(hashtext('security_audit_logs.sequence'));
    SELECT COALESCE(MAX(sequence_no), 0) + 1 INTO expected FROM security_audit_logs;

    IF NEW.sequence_no IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'sequência de auditoria inválida: recebido %, esperado %',
            NEW.sequence_no, expected;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_sequence_guard ON security_audit_logs;
CREATE TRIGGER trg_audit_sequence_guard
    BEFORE INSERT ON security_audit_logs
    FOR EACH ROW EXECUTE FUNCTION fn_audit_sequence_guard();

-- 2. Imutabilidade dos registros -------------------------------------------
CREATE OR REPLACE FUNCTION fn_audit_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION '%.UPDATE bloqueado: logs de auditoria são imutáveis', TG_TABLE_NAME;
    ELSIF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION '%.DELETE bloqueado: logs de auditoria são imutáveis', TG_TABLE_NAME;
    ELSIF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION '%.TRUNCATE bloqueado: logs de auditoria são imutáveis', TG_TABLE_NAME;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_append_only ON security_audit_logs;
CREATE TRIGGER trg_audit_append_only
    BEFORE UPDATE OR DELETE ON security_audit_logs
    FOR EACH ROW EXECUTE FUNCTION fn_audit_append_only();

DROP TRIGGER IF EXISTS trg_audit_no_truncate ON security_audit_logs;
CREATE TRIGGER trg_audit_no_truncate
    BEFORE TRUNCATE ON security_audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION fn_audit_append_only();

-- 3. Âncora externa --------------------------------------------------------
-- O valor em external_ref deve apontar para objeto fora do banco (WORM/S3 Object Lock,
-- commit assinado, ticket imutável). Nunca armazene a chave HMAC aqui.
CREATE TABLE IF NOT EXISTS security_audit_anchors (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    anchored_at   timestamptz NOT NULL DEFAULT now(),
    last_sequence bigint NOT NULL,
    last_hmac     character varying(64) NOT NULL,
    external_ref  text NOT NULL,
    created_by    text NOT NULL DEFAULT current_user,
    CONSTRAINT uk_audit_anchor_external UNIQUE (external_ref),
    CONSTRAINT ck_audit_anchor_hmac CHECK (last_hmac ~ '^[0-9a-f]{64}$')
);

DROP TRIGGER IF EXISTS trg_audit_anchor_append_only ON security_audit_anchors;
CREATE TRIGGER trg_audit_anchor_append_only
    BEFORE UPDATE OR DELETE ON security_audit_anchors
    FOR EACH ROW EXECUTE FUNCTION fn_audit_append_only();

DROP TRIGGER IF EXISTS trg_audit_anchor_no_truncate ON security_audit_anchors;
CREATE TRIGGER trg_audit_anchor_no_truncate
    BEFORE TRUNCATE ON security_audit_anchors
    FOR EACH STATEMENT EXECUTE FUNCTION fn_audit_append_only();

-- 4. Remover privilégios de escrita das contas de aplicação ----------------
-- Revoke explícito para contas que receberam grants diretos no Supabase.
DO $$
DECLARE
    role_record record;
BEGIN
    FOR role_record IN
        SELECT rolname FROM pg_roles
         WHERE rolcanlogin AND rolname <> current_user
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON TABLE security_audit_logs FROM %I',
                       role_record.rolname);
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON TABLE security_audit_anchors FROM %I',
                       role_record.rolname);
    END LOOP;
END $$;

REVOKE UPDATE, DELETE, TRUNCATE ON TABLE security_audit_logs FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE security_audit_anchors FROM PUBLIC;

COMMIT;

-- Verificação pós-migração:
-- SELECT last_value FROM (SELECT sequence_no AS last_value FROM security_audit_logs
--                         ORDER BY sequence_no DESC LIMIT 1) v;
-- UPDATE security_audit_logs SET event_type = 'X' WHERE sequence_no = 1; -- deve falhar
