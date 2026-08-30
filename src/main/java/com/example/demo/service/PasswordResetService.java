package com.example.demo.service;


import com.example.demo.model.PasswordResetToken;
import com.example.demo.model.User;
import com.example.demo.repository.PasswordResetTokenRepository;
import com.example.demo.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;

@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;

    @Transactional
    public String createResetToken(String email, String ipAddress, String userAgent){
        User user = userRepository.findByEmail(email).orElse(null);
        if(user == null) return null;

        tokenRepository.findByUserIdAndUsedFalse(user.getId()).forEach(token -> {
            token.setUsed(true);
            tokenRepository.save(token);
        });

        //generate random token (sent to email)
        byte[] randomBytes = new byte[32];
        new SecureRandom().nextBytes(randomBytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        //genarate hash of the token to save in db
        String tokenHash = hashToken(rawToken);

        PasswordResetToken token = PasswordResetToken.builder()
                .userID(user.getId())
                .tokenHash(tokenHash)
                .expiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
                .used(false)
                .build();

        tokenRepository.save(token);
        auditService.logEvent(user.getId(), "PASSWORD_RESET_REQUIRED", ipAddress, userAgent);

        return rawToken;

    }

    //method to decode token and reset password
    @Transactional
    public void resetPassword(String rawToken, String newPassword, String ipAddress, String userAgent){
        String tokenHash = hashToken(rawToken);

        PasswordResetToken resetToken = tokenRepository.findByTokenHashAndUsedFalse(tokenHash)
                .orElseThrow(() -> new IllegalArgumentException("INVALID OR EXPIRED TOKEN"));

        if(Instant.now().isAfter(resetToken.getExpiresAt())){
            throw new IllegalArgumentException("EXPIRED TOKEN");
        }

        User user = userRepository.findById(resetToken.getUserID())
                .orElseThrow(() -> new IllegalArgumentException("USER NOT FOUND"));

        //update user password
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);

        //set the token as used
        resetToken.setUsed(true);
        tokenRepository.save(resetToken);

        auditService.logEvent(user.getId(), "PASSWORD_RESET_SUCCESS", ipAddress, userAgent);

    }

    private String hashToken(String rawToken){
        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException error){
            throw new RuntimeException("ERROR WHILE GENARATING TOKEN HASH",error);
        }
    }


}

