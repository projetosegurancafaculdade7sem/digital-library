package com.example.demo.service;

import com.example.demo.model.User;
import com.example.demo.model.UserConsent;
import com.example.demo.repository.FavoriteRepository;
import com.example.demo.repository.PasswordResetTokenRepository;
import com.example.demo.repository.UserConsentRepository;
import com.example.demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Direitos do titular (LGPD). A revogação produz efeito real no acesso e a exclusão
 * alcança as tabelas relacionadas (itens 4 e 6 do parecer).
 */
@Service
@RequiredArgsConstructor
public class LgpdService {

    private final UserConsentRepository userConsentRepository;
    private final UserRepository userRepository;
    private final FavoriteRepository favoriteRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final AuditService auditService;

    private static final List<Map<String, String>> DATA_INVENTORY = List.of(
            Map.of("dado", "nome e e-mail", "finalidade", "autenticação e comunicação acadêmica",
                    "baseLegal", "Art. 7º, V (execução de contrato)", "retencao", "enquanto a conta estiver ativa"),
            Map.of("dado", "telefone", "finalidade", "contato e recuperação de acesso",
                    "baseLegal", "Art. 7º, V", "retencao", "até revogação ou exclusão"),
            Map.of("dado", "hash Argon2id e salt", "finalidade", "verificação de credencial",
                    "baseLegal", "Art. 7º, V c/c Art. 5º, II", "retencao", "durante a conta"),
            Map.of("dado", "segredo TOTP", "finalidade", "segundo fator",
                    "baseLegal", "Art. 7º, V", "retencao", "até desativação do 2FA; cifrado em repouso"),
            Map.of("dado", "IP e User-Agent", "finalidade", "auditoria e segurança (Art. 15 do Marco Civil)",
                    "baseLegal", "Art. 7º, V e IX", "retencao", "180 dias, conforme política de retenção"),
            Map.of("dado", "favoritos", "finalidade", "organização acadêmica do estudante",
                    "baseLegal", "Art. 7º, V", "retencao", "até exclusão do titular"),
            Map.of("dado", "tokens de recuperação", "finalidade", "redefinição de senha",
                    "baseLegal", "Art. 7º, V", "retencao", "15 minutos; revogados após uso; HMAC em repouso"),
            Map.of("dado", "cópias de backup", "finalidade", "recuperação de desastre",
                    "baseLegal", "Art. 7º, V e IX", "retencao", "30 dias; restauração reaplica exclusões"),
            Map.of("dado", "registros de auditoria", "finalidade", "segurança e prestação de contas",
                    "baseLegal", "Art. 7º, V e IX", "retencao", "180 dias; cadeia HMAC e âncora externa")
    );

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

        if (!Boolean.TRUE.equals(granted) && UserService.PURPOSE_ACCOUNT.equals(purpose)) {
            userRepository.findById(userId).ifPresent(user -> {
                user.setConsentRevoked(true);
                user.setUpdatedAt(Instant.now());
                userRepository.save(user);
            });
            passwordResetTokenRepository.revokeAllActiveForUser(userId, Instant.now());
        }
        return saved;
    }

    /** Revogação de consentimento pelo titular (req. 4.6). */
    @Transactional
    public UserConsent revokeConsent(UUID userId, String purpose, String termVersion,
                                     String ipAddress, String userAgent) {
        return registerConsent(userId, termVersion, purpose, false, ipAddress, userAgent);
    }

    public List<UserConsent> getUserConsents(UUID userId) {
        return userConsentRepository.findByUserIdOrderByGrantedAtDesc(userId);
    }

    /** Consulta dos dados pessoais do titular (req. 4.8). */
    public Map<String, Object> getPersonalData(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado"));

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("id", user.getId());
        data.put("name", user.getName());
        data.put("email", user.getEmail());
        data.put("phone", user.getPhone());
        data.put("role", user.getRole());
        data.put("twoFactorEnabled", user.isTwoFactorEnabled());
        data.put("consentRevoked", user.isConsentRevoked());
        data.put("createdAt", user.getCreatedAt());
        data.put("updatedAt", user.getUpdatedAt());
        data.put("consents", getUserConsents(userId));
        data.put("favorites", favoriteRepository.findBookIdsByUserId(userId));
        return data;
    }

    /** Exportação estruturada dos dados (req. 4.9). */
    public Map<String, Object> exportPersonalData(UUID userId, String ipAddress, String userAgent) {
        Map<String, Object> export = new LinkedHashMap<>(getPersonalData(userId));
        export.put("exportedAt", Instant.now().toString());
        export.put("format", "JSON");
        export.put("dataInventory", DATA_INVENTORY);
        auditService.logEvent(userId, "LGPD_DATA_EXPORT", ipAddress, userAgent);
        return export;
    }

    /**
     * Exclusão/anonymização do titular (req. 4.10). Favoritos, tokens e consentimentos
     * são removidos; a cadeia de auditoria permanece apenas com o identificador opaco.
     */
    @Transactional
    public void deletePersonalData(UUID userId, String ipAddress, String userAgent) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado"));

        favoriteRepository.deleteByUserId(userId);
        passwordResetTokenRepository.deleteByUserId(userId);
        userConsentRepository.deleteByUserId(userId);

        user.setName("Titular Removido");
        user.setEmail("deleted-" + userId + "@anon.local");
        user.setPhone(null);
        user.setPasswordHash("!");
        user.setPasswordSalt(null);
        user.setTotpSecret(null);
        user.setTwoFactorEnabled(false);
        user.setConsentRevoked(true);
        user.setDeletedAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);

        auditService.logEvent(userId, "LGPD_CONSENT_REVOKED_" + UserService.PURPOSE_ACCOUNT, ipAddress, userAgent);
        auditService.logEvent(userId, "LGPD_DATA_DELETED", ipAddress, userAgent);
    }
}
