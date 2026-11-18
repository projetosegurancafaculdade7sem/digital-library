package com.example.demo.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Nunca persistimos o token de recuperação em claro: gravamos apenas HMAC-SHA256 com
 * domínio separado. Mesmo um vazamento do banco não permite redefinir senhas (item 2).
 */
@Component
public class TokenHasher {

    private static final String ALGORITHM = "HmacSHA256";
    private static final String DOMAIN = "password-reset-token:v1:";

    private final byte[] key;

    public TokenHasher(@Value("${security.audit.hmac-key-base64}") String keyBase64) {
        this.key = Base64.getDecoder().decode(keyBase64);
        if (this.key.length < 32) {
            throw new IllegalStateException("A chave HMAC de auditoria deve ter ao menos 32 bytes.");
        }
    }

    public String hash(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("Token vazio");
        }
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(key, ALGORITHM));
            byte[] digest = mac.doFinal((DOMAIN + rawToken).getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao calcular HMAC do token", e);
        }
    }

    /** Usado apenas para equalizar o tempo de resposta entre e-mails existentes e inexistentes. */
    public String dummyHash() {
        return hash("dummy-token-for-timing-equalization");
    }
}
