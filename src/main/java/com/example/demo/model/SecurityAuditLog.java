package com.example.demo.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

/**
 * Log de auditoria append-only. A cadeia usa HMAC-SHA256 com chave fora do banco e
 * número de sequência monotônico (item 5 do parecer). UPDATE/DELETE são bloqueados
 * tanto pelo JPA quanto pela migração SQL em docs/sql/audit-hardening.sql.
 */
@Entity
@Table(name = "security_audit_logs", indexes = {
        @Index(name = "idx_audit_timestamp", columnList = "timestamp"),
        @Index(name = "idx_audit_user_id", columnList = "user_id"),
        @Index(name = "idx_audit_sequence", columnList = "sequence_no")
}, uniqueConstraints = {
        @UniqueConstraint(name = "uk_audit_sequence", columnNames = "sequence_no")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "sequence_no", nullable = false, updatable = false)
    private Long sequenceNo;

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "event_type", nullable = false, length = 100)
    private String eventType;

    @Column(name = "ip_address", nullable = false, length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(name = "timestamp", nullable = false, updatable = false)
    private Instant timestamp;

    @Column(name = "previous_hash", nullable = false, length = 64, updatable = false)
    private String previousHash;

    @Column(name = "hmac_hash", nullable = false, length = 64, updatable = false)
    private String hmacHash;

    /** Mantido para compatibilidade com consultas e painéis antigos. */
    @Column(name = "log_hash", nullable = false, length = 64, updatable = false)
    private String logHash;

    @PrePersist
    protected void onCreate() {
        if (this.timestamp == null) {
            this.timestamp = Instant.now();
        }
    }

    @PreUpdate
    protected void blockUpdate() {
        throw new UnsupportedOperationException("Registros de auditoria são imutáveis");
    }

    @PreRemove
    protected void blockRemove() {
        throw new UnsupportedOperationException("Registros de auditoria não podem ser excluídos");
    }
}
