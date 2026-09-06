package com.example.demo.service;
import com.example.demo.model.PasswordResetToken;
import com.example.demo.model.User;
import com.example.demo.repository.PasswordResetTokenRepository;
import com.example.demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;



@Service
@RequiredArgsConstructor
public class PasswordResetService {
    private static final SecureRandom secureRandom = new SecureRandom();
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    // Helper method for secure token generation
    private String generateSecureToken() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
    @Transactional
    public String createResetToken(String email, String clientIp, String userAgent) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isEmpty()) {
            // Mitigation of user enumeration – do not reveal existence
            return null;
        }
        User user = userOptional.get();
        String token = generateSecureToken();
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
        return token;
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
