package com.example.demo.service;

import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Autenticação primária, 2FA TOTP e bloqueio por tentativas.
 * Os handlers do formLogin ({@code LoginAuthentication*Handler}) delegam
 * o registro de falhas/sucessos a este serviço, garantindo que o fluxo
 * real da UI execute as mesmas regras (req. 1.6 / 1.11 / 5.1 / 5.2).
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;
    private final TwoFactorService twoFactorService;

    private static final int MAX_FAILED_ATTEMPTS = 5;

    @Transactional
    public User authenticatePrimary(String email, String rawPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));

        ensureNotLocked(user);

        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            throw new IllegalStateException("Invalid credentials");
        }
        return user;
    }

    public boolean verify2FACode(User user, String totpCode) {
        return twoFactorService.verifyCode(user.getTotpSecret(), totpCode);
    }

    /**
     * Autenticação completa (senha + TOTP) — disponível para clientes API/testes.
     * O fluxo web usa formLogin + /login-2fa, que reutiliza as mesmas regras.
     */
    @Transactional
    public User authenticate(String email, String rawPassword, String totpcode,
                             String ipAddress, String userAgent) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> {
            auditService.logEvent(null, "LOGIN_FAILED_UNKNOWN_USER", ipAddress, userAgent);
            return new IllegalArgumentException("Invalid Credentials");
        });

        ensureNotLocked(user);

        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            handleFailedLogin(user, ipAddress, userAgent);
            throw new IllegalArgumentException("invalid credentials");
        }

        if (user.isTwoFactorEnabled()) {
            if (!twoFactorService.verifyCode(user.getTotpSecret(), totpcode)) {
                handleFailedLogin(user, ipAddress, userAgent);
                auditService.logEvent(user.getId(), "LOGIN_FAILED_2FA", ipAddress, userAgent);
                throw new IllegalArgumentException("2FA code invalid or expired!");
            }
        }

        user.setFailedLoginAttempts(0);
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);

        auditService.logEvent(user.getId(), "LOGIN_SUCCESS", ipAddress, userAgent);
        return user;
    }

    /**
     * Chamado pelo failure handler do formLogin após senha inválida.
     * @return true se a conta ficou bloqueada
     */
    @Transactional
    public boolean registerFailedPasswordAttempt(String email, String ipAddress, String userAgent) {
        if (email == null || email.isBlank()) {
            auditService.logEvent(null, "LOGIN_FAILED_UNKNOWN_USER", ipAddress, userAgent);
            return false;
        }
        return userRepository.findByEmail(email)
                .map(user -> {
                    handleFailedLogin(user, ipAddress, userAgent);
                    return !user.isAccountNonLocked();
                })
                .orElseGet(() -> {
                    auditService.logEvent(null, "LOGIN_FAILED_UNKNOWN_USER", ipAddress, userAgent);
                    return false;
                });
    }

    @Transactional
    public boolean registerFailed2FAAttempt(String email, String ipAddress, String userAgent) {
        return userRepository.findByEmail(email)
                .map(user -> {
                    handleFailedLogin(user, ipAddress, userAgent);
                    auditService.logEvent(user.getId(), "LOGIN_FAILED_2FA", ipAddress, userAgent);
                    return !user.isAccountNonLocked();
                })
                .orElse(false);
    }

    @Transactional
    public void registerSuccessful2FA(String email, String ipAddress, String userAgent) {
        userRepository.findByEmail(email).ifPresent(user -> {
            user.setFailedLoginAttempts(0);
            user.setUpdatedAt(Instant.now());
            userRepository.save(user);
            auditService.logEvent(user.getId(), "LOGIN_SUCCESS_2FA", ipAddress, userAgent);
        });
    }

    private void ensureNotLocked(User user) {
        if (!user.isAccountNonLocked()) {
            if (user.getLockedUntil() != null && Instant.now().isAfter(user.getLockedUntil())) {
                user.setAccountNonLocked(true);
                user.setFailedLoginAttempts(0);
                user.setLockedUntil(null);
                userRepository.save(user);
            } else {
                throw new IllegalStateException("account temporarily locked, try again later");
            }
        }
    }

    private void handleFailedLogin(User user, String ipAddress, String userAgent) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);
        user.setUpdatedAt(Instant.now());

        if (attempts >= MAX_FAILED_ATTEMPTS) {
            user.setAccountNonLocked(false);
            user.setLockedUntil(Instant.now().plus(15, ChronoUnit.MINUTES));
            auditService.logEvent(user.getId(), "ACCOUNT_LOCKED_MAX_ATTEMPTS", ipAddress, userAgent);
        } else {
            auditService.logEvent(user.getId(), "LOGIN_FAILED_BAD_CREDENTIALS", ipAddress, userAgent);
        }
        userRepository.save(user);
    }
}
