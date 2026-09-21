package com.example.demo.service;

import com.example.demo.model.User;
import com.example.demo.model.UserConsent;
import com.example.demo.repository.UserConsentRepository;
import com.example.demo.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Direitos do titular (LGPD) — fluxo documentado em docs/SEGURANCA.md (req. 4.11).
 */
@Service
@RequiredArgsConstructor
public class LgpdService {

    private final UserConsentRepository userConsentRepository;
    private final UserRepository userRepository;
    private final AuditService auditService;

    @Transactional
    public UserConsent registerConsent(UUID userId, String termVersion, String purpose,
                                       Boolean granted, String ipAddress, String userAgent) {
        UserConsent consent = UserConsent.builder()
                .userId(userId)
                .termVersion(termVersion)
                .purpose(purpose)
                .granted(granted)
                .grantedAt(Instant.now())
                .ipAddress(ipAddress != null ? ipAddress : "unknown")
                .build();

        UserConsent saved = userConsentRepository.save(consent);

        String event = Boolean.TRUE.equals(granted) ? "LGPD_CONSENT_GRANTED" : "LGPD_CONSENT_REVOKED";
        auditService.logEvent(userId, event + "_" + purpose, ipAddress, userAgent);

        return saved;
    }

    /**
     * Revogação de consentimento pelo titular (req. 4.6).
     */
    @Transactional
    public UserConsent revokeConsent(UUID userId, String purpose, String termVersion,
                                     String ipAddress, String userAgent) {
        return registerConsent(userId, termVersion, purpose, false, ipAddress, userAgent);
    }

    public List<UserConsent> getUserConsents(UUID userId) {
        return userConsentRepository.findByUserIdOrderByGrantedAtDesc(userId);
    }

    /**
     * Consulta dos dados pessoais do titular (req. 4.8).
     */
    public Map<String, Object> getPersonalData(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado"));

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("id", user.getId());
        data.put("name", user.getName());
        data.put("email", user.getEmail());
        data.put("role", user.getRole());
        data.put("twoFactorEnabled", user.isTwoFactorEnabled());
        data.put("createdAt", user.getCreatedAt());
        data.put("updatedAt", user.getUpdatedAt());
        data.put("consents", getUserConsents(userId));
        return data;
    }

    /**
     * Exportação estruturada dos dados (req. 4.9).
     */
    public Map<String, Object> exportPersonalData(UUID userId) {
        Map<String, Object> export = new HashMap<>(getPersonalData(userId));
        export.put("exportedAt", Instant.now().toString());
        export.put("format", "JSON");
        auditService.logEvent(userId, "LGPD_DATA_EXPORT", null, null);
        return export;
    }

    /**
     * Exclusão / anonimização dos dados pessoais (req. 4.10).
     */
    @Transactional
    public void deletePersonalData(UUID userId, String ipAddress, String userAgent) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado"));

        String anonymized = "deleted-" + userId + "@anon.local";
        user.setName("Titular Removido");
        user.setEmail(anonymized);
        user.setPasswordHash("!");
        user.setPasswordSalt(null);
        user.setTotpSecret(null);
        user.setTwoFactorEnabled(false);
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);

        registerConsent(userId, UserService.TERMS_VERSION, UserService.PURPOSE_ACCOUNT,
                false, ipAddress, userAgent);
        auditService.logEvent(userId, "LGPD_DATA_DELETED", ipAddress, userAgent);
    }
}
