package com.example.demo.service;

import com.example.demo.model.PasswordResetToken;
import com.example.demo.model.User;
import com.example.demo.repository.PasswordResetTokenRepository;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.PasswordHashingSupport;
import com.example.demo.security.PasswordPolicy;
import com.example.demo.security.TokenHasher;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Recuperação de senha: token de 256 bits, HMAC em repouso, 15 minutos de validade,
 * uso único atômico, invalidação da sessão anterior e política de nova senha (item 2).
 */
@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int TOKEN_VALIDITY_MINUTES = 15;

    private final PasswordResetTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final PasswordHashingSupport passwordHashingSupport;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final TokenHasher tokenHasher;
    private final AuditService auditService;
    private final SessionTerminationService sessionTerminationService;

    /**
     * @return token em claro apenas quando o e-mail existe; {@code null} caso contrário.
     * O chamador deve sempre responder da mesma forma (anti-enumeração).
     */
    @Transactional
    public String createResetToken(String email, String clientIp, String userAgent) {
        Instant now = Instant.now();
        Optional<User> maybeUser = userRepository.findByLoginEmail(email);

        if (maybeUser.isEmpty()) {
            // Mesmo custo computacional para e-mail inexistente — sem vazamento por timing.
            tokenHasher.dummyHash();
            auditService.logEvent(null, "PASSWORD_RESET_REQUEST", clientIp, userAgent);
            return null;
        }

        User user = maybeUser.get();
        tokenRepository.revokeAllActiveForUser(user.getId(), now);

        String token = generateSecureToken();
        PasswordResetToken resetToken = PasswordResetToken.builder()
                .tokenHash(tokenHasher.hash(token))
                .userId(user.getId())
                .expiresAt(now.plus(TOKEN_VALIDITY_MINUTES, ChronoUnit.MINUTES))
                .used(false)
                .clientIp(clientIp)
                .userAgent(userAgent)
                .createdAt(now)
                .build();
        tokenRepository.save(resetToken);

        // userId propositalmente nulo: o log não permite associar a solicitação ao titular.
        auditService.logEvent(null, "PASSWORD_RESET_REQUEST", clientIp, userAgent);
        return token;
    }

    /** Validação usada pela tela, sem revelar se o e-mail existe. */
    public boolean isTokenUsable(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        return tokenRepository.findByTokenHash(tokenHasher.hash(token))
                .filter(t -> !t.isUsed() && t.getRevokedAt() == null)
                .filter(t -> t.getExpiresAt().isAfter(Instant.now()))
                .isPresent();
    }

    @Transactional
    public void resetPassword(String token, String newPassword, String clientIp, String userAgent) {
        List<String> policyErrors = passwordPolicy.violations(newPassword);
        if (!policyErrors.isEmpty()) {
            auditService.logEvent(null, "PASSWORD_RESET_FAILURE_POLICY", clientIp, userAgent);
            throw new IllegalArgumentException(String.join(" ", policyErrors));
        }

        String hash = tokenHasher.hash(token == null ? "" : token);
        PasswordResetToken resetToken = tokenRepository.findByTokenHashForUpdate(hash)
                .orElseThrow(() -> {
                    auditService.logEvent(null, "PASSWORD_RESET_FAILURE", clientIp, userAgent);
                    return new IllegalArgumentException("Token inválido ou expirado.");
                });

        Instant now = Instant.now();
        if (resetToken.isUsed() || resetToken.getRevokedAt() != null
                || !resetToken.getExpiresAt().isAfter(now)) {
            auditService.logEvent(null, "PASSWORD_RESET_FAILURE", clientIp, userAgent);
            throw new IllegalStateException("Token inválido ou expirado. Solicite uma nova recuperação.");
        }

        User user = userRepository.findById(resetToken.getUserID())
                .orElseThrow(() -> new IllegalStateException("Token inválido ou expirado."));

        passwordPolicy.validateNewPassword(newPassword, user.getPasswordHash(), passwordEncoder);

        // CAS atômico: concorrência não permite dois usos do mesmo token.
        int consumed = tokenRepository.consumeIfUnused(resetToken.getId(), now);
        if (consumed != 1) {
            auditService.logEvent(null, "PASSWORD_RESET_FAILURE_REPLAY", clientIp, userAgent);
            throw new IllegalStateException("Token inválido ou expirado. Solicite uma nova recuperação.");
        }

        PasswordHashingSupport.EncodedPassword encoded = passwordHashingSupport.encode(newPassword);
        user.setPasswordHash(encoded.hash());
        user.setPasswordSalt(encoded.salt());
        user.setFailedLoginAttempts(0);
        user.setAccountNonLocked(true);
        user.setLockedUntil(null);
        user.setUpdatedAt(now);
        userRepository.save(user);

        tokenRepository.revokeAllActiveForUser(user.getId(), now);
        // Invalida as sessões abertas com a senha anterior (prometido na documentação do item 2).
        sessionTerminationService.expireAllSessions(user.getEmail());
        auditService.logEvent(null, "PASSWORD_RESET_SUCCESS", clientIp, userAgent);
    }

    private String generateSecureToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
