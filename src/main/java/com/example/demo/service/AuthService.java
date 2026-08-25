package com.example.demo.service;


import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.TotpManager;
import jakarta.transaction.Transactional;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.chrono.ChronoPeriod;
import java.time.temporal.ChronoUnit;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TotpManager totpManager;
    private final AuditService auditService;


    private static final int MAX_FAILED_ATTEMPTS = 5;

    @Transactional
    public User authenticate(String email, String rawPassword, String totpcode, String ipAddress, String userAgent) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> {
            auditService.logEvent(null, "LOGIN_FAILE_UNKNOWN_USER", ipAddress, userAgent);
            return new IllegalArgumentException("Invalid Credentials");
        });

        // Verify if the account is temporarily locked
        if (Boolean.FALSE.equals(user.isAccountNonLocked())) {
            if (user.getLockedUntil() != null && Instant.now().isAfter(user.getLockedUntil())) {
                //blocks time expired, unlock account
                user.setAccountNonLocked(true);
                user.setFailedLoginAttempts(0);
                user.setLockedUntil(null);
            } else {
                auditService.logEvent(user.getId(), "LOGIN_BLOCK_ATTEMP", ipAddress, userAgent);
                throw new IllegalStateException("account temporarily locked, try again later :-( ");
            }

        }
        //Validate password
        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            handleFailedLogin(user, ipAddress, userAgent);
            throw new IllegalArgumentException("invalid credentials");
        }

        //validate if 2FA is enabled
        if (Boolean.TRUE.equals(user.is_2fa_enabled())) {
            if (!totpManager.verifyCode(user.getTotpSecret(), totpcode)) {
                handleFailedLogin(user, ipAddress, userAgent);
                throw new IllegalArgumentException("2FA code invalid or expired!")
            }
        }

        // if login succeeded, reset fails attemps
        user.setFailedLoginAttempts(0);
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);

        auditService.logEvent(user.getId, "LOGIN_SUCCESS", ipAddress, userAgent);
        return user;


    }
    private void handleFailedLogin(User user, String ipAddress, String userAgent){
        int attemps = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attemps);
        user.setUpdatedAt(Instant.now());

        if(attemps >= MAX_FAILED_ATTEMPTS){
            user.setAccountNonLocked(false);
            //block account for 15 minutes
            user.setLockedUntil(Instant.now().plus(15, ChronoUnit.MINUTES));
            auditService.logEvent(user.getId(), "ACCOUNT_LOCKED_MAX_ATTEMPTS", ipAddress, userAgent);

        }else {
            auditService.logEvent(user.getId(), "LOGIN_FAILED_BAD_CREDENTIALS", ipAddress, userAgent);
        }
        userRepository.save(user);
    }
}