package com.example.demo.security;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Auxilia o armazenamento explícito do salt gerado pelo Argon2 (PHC string).
 * O {@link org.springframework.security.crypto.argon2.Argon2PasswordEncoder}
 * já incorpora o salt no hash; este suporte extrai o salt para o campo
 * {@code passwordSalt}, atendendo ao armazenamento separado hash + salt.
 */
@Component
public class PasswordHashingSupport {

    private final PasswordEncoder passwordEncoder;

    public PasswordHashingSupport(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public EncodedPassword encode(String rawPassword) {
        String encoded = passwordEncoder.encode(rawPassword);
        return new EncodedPassword(encoded, extractSalt(encoded));
    }

    /**
     * Formato PHC do Argon2: {@code $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>}
     */
    public static String extractSalt(String argon2Encoded) {
        if (argon2Encoded == null || argon2Encoded.isBlank()) {
            return null;
        }
        String[] parts = argon2Encoded.split("\\$");
        // "", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"
        if (parts.length >= 5) {
            return parts[4];
        }
        return null;
    }

    public record EncodedPassword(String hash, String salt) {}
}
