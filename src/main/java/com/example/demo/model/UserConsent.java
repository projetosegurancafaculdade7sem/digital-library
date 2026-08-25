package com.example.demo.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_consents", indexes = {
        @Index(name = "idx_user_consent_user_id", columnList = "user_id")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserConsent {

        @Id
        @GeneratedValue(strategy = GenerationType.UUID)
        private UUID id;

        @Column(name = "user_id", nullable = false)
        private UUID userId;

        @Column(name = "termVersion", nullable = false, length = 20)
        private String termVersion;

        @Column(name = "purpose", nullable = false, length = 100)
        private String purpose;

        @Column(name = "granted", nullable = false)
        private Boolean granted;

        @Column(name = "granted_at", nullable = false, updatable = false)
        private Instant grantedAt;

        @Column(name = "ip_address", nullable = false, length = 45)
        private String ipAddress;

        @PrePersist
        protected void onCreate(){
                if (this.grantedAt == null){
                        this.grantedAt = Instant.now();
                }
        }
}
