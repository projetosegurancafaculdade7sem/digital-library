package com.example.demo.model;

import com.example.demo.security.AttributeEncryptor;
import jakarta.persistence.*;
import lombok.Data;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name ="tb_users")
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String email;

    //Hash da senha (Argon2) - requisito 1.1
    @Column(name= "passwordHash", nullable = false)
    private String passwordHash;

    //Salt criptografico para auditoria requisito 1.3 e 1.4
    @Column(name = "passwordSalt", nullable = false)
    private String passwordSalt;

    //status 2fa requisito 1.5
    @Column(name = "is_2fa_enabled", nullable = false)
    private boolean is_2fa_enabled;

    //secret do totp criptografado em repouso com AES-256 via AttributeEncryptor
    @Convert(converter = AttributeEncryptor.class)
    @Column(name = "totpSecret")
    private String totpSecret;

    //Proteção contra brute force e bloqueio de conta requisitos 1.11
    @Column(name = "accountNonLocked", nullable = false)
    private boolean accountNonLocked;

    // controle de tentativas de login
    @Column(name ="failedLoginAttempts", nullable = false)
    private Integer failedLoginAttempts;

    @Column(name ="lockedUntil")
    private Instant lockedUntil;

    // auditoria temporal
    @Column(name = "createdAt", nullable = false, updatable = false)
    private Instant createdAt;

    // auditoria temporal
    @Column(name = "updatedAt", nullable = false)
    private Instant updatedAt;


    public User(){}

    @PrePersist
    protected void onCreate(){
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
    }


    @PreUpdate
    protected void onUpdate(){
        this.updatedAt = Instant.now();
    }


}
