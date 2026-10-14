package com.example.demo.service;

import com.example.demo.dto.request.RegisterRequest;
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.PasswordHashingSupport;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final TwoFactorService twoFactorService;
    private final UserRepository userRepository;
    private final PasswordHashingSupport passwordHashingSupport;
    private final LgpdService lgpdService;

    @PersistenceContext
    private EntityManager entityManager;

    public static final String TERMS_VERSION = "1.0";
    public static final String PURPOSE_ACCOUNT = "CRIACAO_CONTA_ACADEMICA";

    /**
     * Resultado do cadastro com o segredo TOTP em claro somente para exibir o QR
     * (não usar o valor eventualmente alterado pelo ciclo JPA/criptografia).
     */
    public record RegistrationResult(User user, String totpSecretPlaintext) {}

    @Transactional
    public RegistrationResult registerUser(RegisterRequest request, String name, String ipAddress, String userAgent) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("E-mail not available.");
        }
        if (!request.isAcceptTerms()) {
            throw new IllegalArgumentException("É necessário aceitar os termos de uso e a política de privacidade.");
        }

        PasswordHashingSupport.EncodedPassword encoded =
                passwordHashingSupport.encode(request.getPassword());

        // Guardamos o plaintext ANTES do save — o AttributeEncryptor cifra só na coluna do banco.
        String totpSecretPlaintext = twoFactorService.generateSecret();

        User user = new User();
        user.setName(name != null && !name.isBlank() ? name : request.getEmail());
        user.setEmail(request.getEmail());
        user.setPasswordHash(encoded.hash());
        user.setPasswordSalt(encoded.salt());
        user.setTotpSecret(totpSecretPlaintext);
        user.setTwoFactorEnabled(true);
        user.setRole("ROLE_USER");
        user.setAccountNonLocked(true);
        user.setFailedLoginAttempts(0);
        user.setCreatedAt(Instant.now());

        User saved = userRepository.saveAndFlush(user);

        // Limpa o 1º nível do JPA para forçar leitura do banco (com decrypt)
        entityManager.clear();
        User reloaded = userRepository.findById(saved.getId())
                .orElseThrow(() -> new IllegalStateException("Falha ao recarregar usuário após cadastro"));
        String persistedSecret = reloaded.getTotpSecret();
        if (persistedSecret == null || !persistedSecret.replace(" ", "").equalsIgnoreCase(totpSecretPlaintext.replace(" ", ""))) {
            throw new IllegalStateException(
                    "Falha na persistência do segredo TOTP (criptografia/conversão). Tente cadastrar novamente.");
        }

        lgpdService.registerConsent(
                saved.getId(),
                TERMS_VERSION,
                PURPOSE_ACCOUNT,
                true,
                ipAddress,
                userAgent
        );

        return new RegistrationResult(reloaded, totpSecretPlaintext);
    }

    @Transactional
    public String setup2FA(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found!"));

        if (user.getTotpSecret() == null || user.getTotpSecret().isEmpty()) {
            String secret = twoFactorService.generateSecret();
            user.setTotpSecret(secret);
            userRepository.save(user);
        }
        return user.getTotpSecret();
    }

    @Transactional
    public void enable2FA(UUID userId, String code) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found!"));

        boolean isValid = twoFactorService.verifyCode(user.getTotpSecret(), code);
        if (!isValid) {
            throw new IllegalArgumentException("Invalid 2FA code!");
        }
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
    }

    @Transactional
    public User findById(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("user not found with id: " + id));
    }

    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("user not found: " + email));
    }
}
