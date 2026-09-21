package com.example.demo.security;

import com.example.demo.service.TwoFactorService;
import org.springframework.stereotype.Component;

/**
 * Fachada mantida por compatibilidade. A implementação canônica de TOTP
 * é {@link TwoFactorService} — evita duplicidade de algoritmos 2FA.
 */
@Component
public class TotpManager {

    private final TwoFactorService twoFactorService;

    public TotpManager(TwoFactorService twoFactorService) {
        this.twoFactorService = twoFactorService;
    }

    public String generateSecretKey() {
        return twoFactorService.generateSecret();
    }

    public boolean verifyCode(String secret, String code) {
        return twoFactorService.verifyCode(secret, code);
    }

    public String getQrCodeUrl(String email, String secret, String appName) {
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s",
                appName, email, secret, appName);
    }
}
