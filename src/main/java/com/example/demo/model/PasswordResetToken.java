package com.example.demo.model;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "password_reset_token", indexes = {
        @Index(name = "idx_reset_token_hash", columnList = "token_hash", unique = true),
        @Index(name = "idx_reset_token_user_id", columnList = "user_id")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PasswordResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private UUID userID;

    @Column(name = "token_hash", nullable = false, unique = true, length = 128)
    private String tokenHash;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "used", nullable = false)
    private boolean used;

    public boolean isValid(){

        return Boolean.FALSE.equals(this.used) && Instant.now().isBefore(this.expiresAt);
    }
}
