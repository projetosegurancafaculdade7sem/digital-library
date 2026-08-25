package com.example.demo.model;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "security_audit_logs", indexes = {
        @Index(name = "idx_audit_timestamp", columnList = "timestamp"),
        @Index(name = "idx_audit_user_id", columnList = "user_id")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

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

    @Column(name = "log_hash", nullable = false, length = 64, updatable = false)
    private String logHash;

    @PrePersist
    protected void onCreate(){
        if(this.timestamp == null){
            this.timestamp = Instant.now();
        }
    }
}
