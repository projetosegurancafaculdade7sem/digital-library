package com.example.demo.service;

import com.example.demo.model.Favorite;
import com.example.demo.model.PasswordResetToken;
import com.example.demo.model.User;
import com.example.demo.repository.FavoriteRepository;
import com.example.demo.repository.PasswordResetTokenRepository;
import com.example.demo.repository.UserConsentRepository;
import com.example.demo.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/** Efeitos de revogação, exportação e exclusão em tabelas relacionadas (item 4). */
@SpringBootTest
@ActiveProfiles("test")
class LgpdServiceTest {

    @Autowired private LgpdService lgpdService;
    @Autowired private PasswordResetService passwordResetService;
    @Autowired private UserRepository userRepository;
    @Autowired private FavoriteRepository favoriteRepository;
    @Autowired private UserConsentRepository consentRepository;
    @Autowired private PasswordResetTokenRepository tokenRepository;

    private User createUser() {
        return userRepository.saveAndFlush(User.builder()
                .name("Titular LGPD")
                .email("lgpd-" + UUID.randomUUID() + "@faculdade.edu.br")
                .passwordHash("!")
                .twoFactorEnabled(true)
                .twoFactorSecret("JBSWY3DPEHPK3PXP")
                .build());
    }

    @Test
    void revogacaoDaContaBloqueiaAcessoImediatamente() {
        User user = createUser();
        lgpdService.registerConsent(user.getId(), UserService.TERMS_VERSION,
                UserService.PURPOSE_ACCOUNT, true, "127.0.0.1", "JUnit");

        assertFalse(userRepository.findById(user.getId()).orElseThrow().isConsentRevoked());

        lgpdService.revokeConsent(user.getId(), UserService.PURPOSE_ACCOUNT,
                UserService.TERMS_VERSION, "127.0.0.1", "JUnit");

        assertTrue(userRepository.findById(user.getId()).orElseThrow().isConsentRevoked());
        assertEquals(2, consentRepository.findByUserIdOrderByGrantedAtDesc(user.getId()).size());
    }

    @Test
    void exportacaoIncluiFavoritosEinventario() {
        User user = createUser();
        Favorite favorite = new Favorite();
        favorite.setUser(user);
        favorite.setBookId("ISBN-978-85-TESTE");
        favorite.setCreatedAt(Instant.now());
        favoriteRepository.saveAndFlush(favorite);

        Map<String, Object> export = lgpdService.exportPersonalData(user.getId(), "127.0.0.1", "JUnit");

        assertEquals(user.getId(), export.get("id"));
        assertTrue(((java.util.List<?>) export.get("favorites")).contains("ISBN-978-85-TESTE"));
        assertNotNull(export.get("dataInventory"));
        assertNotNull(export.get("exportedAt"));
    }

    @Test
    void exclusaoAnonimizaEApagaTabelasRelacionadas() {
        User user = createUser();
        lgpdService.registerConsent(user.getId(), UserService.TERMS_VERSION,
                UserService.PURPOSE_ACCOUNT, true, "127.0.0.1", "JUnit");

        Favorite favorite = new Favorite();
        favorite.setUser(user);
        favorite.setBookId("ISBN-APAGAR");
        favorite.setCreatedAt(Instant.now());
        favoriteRepository.saveAndFlush(favorite);

        String rawToken = passwordResetService.createResetToken(user.getEmail(), "127.0.0.1", "JUnit");
        assertNotNull(rawToken);
        assertFalse(tokenRepository.findByUserId(user.getId()).isEmpty());

        lgpdService.deletePersonalData(user.getId(), "127.0.0.1", "JUnit");

        User deleted = userRepository.findById(user.getId()).orElseThrow();
        assertTrue(deleted.getEmail().startsWith("deleted-"));
        assertNull(deleted.getPhone());
        assertNull(deleted.getTotpSecret());
        assertTrue(deleted.isConsentRevoked());
        assertNotNull(deleted.getDeletedAt());

        assertTrue(favoriteRepository.findBookIdsByUserId(user.getId()).isEmpty());
        assertTrue(consentRepository.findByUserIdOrderByGrantedAtDesc(user.getId()).isEmpty());
        assertTrue(tokenRepository.findByUserId(user.getId()).isEmpty());
    }
}
