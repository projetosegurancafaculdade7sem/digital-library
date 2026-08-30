package com.example.demo.service;

import com.example.demo.model.UserConsent;
import com.example.demo.repository.UserConsentRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class LgpdService {

    private final UserConsentRepository userConsentRepository;
    private final AuditService auditService;

    @Transactional
    public UserConsent registerConsent(UUID userId, String termVersion, String purpose, Boolean granted, String ipAddress, String userAgent){

        UserConsent consent = UserConsent.builder()
                .userId(userId)
                .termVersion(termVersion)
                .purpose(purpose)
                .granted(granted)
                .grantedAt(Instant.now())
                .ipAddress(ipAddress)
                .build();

        UserConsent saved = userConsentRepository.save(consent);

        String event = Boolean.TRUE.equals(granted) ? "LGPD_CONSENT_GRANTED" : "LGPD_CONSENT_REVOKED";
        auditService.logEvent(userId, event + "_" + purpose, ipAddress, userAgent);

        return saved;
    }

    public List<UserConsent> getUserConsents(UUID userId){
    return userConsentRepository.findByUserIdOrderByGrantedAtDesc(userId);

    }
}
