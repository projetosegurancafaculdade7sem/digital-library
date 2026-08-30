package com.example.demo.service;

import com.example.demo.model.PasswordResetToken;
import com.example.demo.model.User;
import com.example.demo.repository.PasswordResetTokenRepository;
import com.example.demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void createResetToken(String email, String clientIp, String userAgent) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isEmpty()) {
            // Mitigação de User Enumeration (Requisito 1.8)
            return;
        }

        User user = userOptional.get();
        String token = UUID.randomUUID().toString();

        PasswordResetToken resetToken = PasswordResetToken.builder()
                .token(token)
                .userId(user.getId())
                .expiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
                .used(false)
                .clientIp(clientIp)
                .userAgent(userAgent)
                .createdAt(Instant.now())
                .build();

        passwordResetTokenRepository.save(resetToken);
        System.out.println(">>> LINK DE RECUPERAÇÃO: http://localhost:8080/reset-password?token=" + token);
    }

    @Transactional
    public void resetPassword(String token, String newPassword, String clientIp, String userAgent) {
        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Token inválido ou não encontrado."));

        if (resetToken.isUsed()) {
            throw new IllegalStateException("Este token já foi utilizado.");
        }

        if (resetToken.getExpiresAt().isBefore(Instant.now())) {
            throw new IllegalStateException("O token expirou. Solicite uma nova recuperação.");
        }

        User user = userRepository.findById(resetToken.getUserID())
                .orElseThrow(() -> new IllegalArgumentException("Usuário associado não encontrado."));

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        resetToken.setUsed(true);
        passwordResetTokenRepository.save(resetToken);
    }
}