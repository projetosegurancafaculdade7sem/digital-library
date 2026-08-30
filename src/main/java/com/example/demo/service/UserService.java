package com.example.demo.service;


import com.example.demo.dto.request.RegisterRequest;
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final TwoFactorService twoFactorService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public User registerUser(RegisterRequest request){
        if(userRepository.existsByEmail(request.getEmail())){
            throw new IllegalArgumentException("E-mail not available.");
        }

        String encodedPassword = passwordEncoder.encode(request.getPassword());

        byte[] rawSalt = new byte[16];

        new SecureRandom().nextBytes(rawSalt);
        String saltBase64 = Base64.getEncoder().encodeToString(rawSalt);

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPasswordHash(encodedPassword);
        user.setPasswordSalt(saltBase64);
        user.set_2fa_enabled(false);
        user.setAccountNonLocked(true);
        user.setFailedLoginAttempts(0);

        return userRepository.save(user);
    }

    @Transactional
    public String setup2FA(UUID userId){
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found!"));

        // if it doesn't have a secret, create a new one
        if(user.getTotpSecret() == null || user.getTotpSecret().isEmpty()){
            String secret = twoFactorService.generateSecret();
            user.setTotpSecret(secret); // Encrypted record via AttributeEncryptor
            userRepository.save(user);
        }
        return user.getTotpSecret();
    }


    //Enable 2FA if's not.
    @Transactional
    public void enable2FA(UUID userId, String code){
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found!"));

        boolean isValid = twoFactorService.verifyCode(user.getTotpSecret(), code);
            if(!isValid){
                throw new IllegalArgumentException("Ivalid 2FA code!");
            }
            user.set_2fa_enabled(true);
            userRepository.save(user);
        }

    @Transactional
    public User findById(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("user not found with id: " + id));
    }
    }

