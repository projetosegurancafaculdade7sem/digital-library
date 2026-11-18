package com.example.demo.service;

import com.example.demo.model.PasswordResetToken;
import com.example.demo.model.User;
import com.example.demo.repository.PasswordResetTokenRepository;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.PasswordHashingSupport;
import com.example.demo.security.PasswordPolicy;
import com.example.demo.security.TokenHasher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/** Evidências de expiração, uso único, concorrência, política e anti-enumeração (item 2). */
@SpringBootTest
@ActiveProfiles("test")
class PasswordResetServiceTest {

    private static final String CURRENT_PASSWORD = "SenhaAtual@2026";
    private static final String NEW_PASSWORD = "NovaSenha@2026Segura";

    @Autowired private PasswordResetService service;
    @Autowired private UserRepository userRepository;
    @Autowired private PasswordResetTokenRepository tokenRepository;
    @Autowired private PasswordHashingSupport hashingSupport;
    @Autowired private TokenHasher tokenHasher;
    @Autowired private PasswordPolicy passwordPolicy;

    private User user;

    @BeforeEach
    void setUp() {
        user = createUser("reset-" + UUID.randomUUID() + "@faculdade.edu.br");
    }

    private User createUser(String email) {
        PasswordHashingSupport.EncodedPassword encoded = hashingSupport.encode(CURRENT_PASSWORD);
        return userRepository.saveAndFlush(User.builder()
                .name("Usuario Reset")
                .email(email)
                .passwordHash(encoded.hash())
                .passwordSalt(encoded.salt())
                .twoFactorEnabled(true)
                .twoFactorSecret("JBSWY3DPEHPK3PXP")
                .build());
    }

    @Test
    void tokenNaoEArmazenadoEmClaro() {
        String raw = service.createResetToken(user.getEmail(), "127.0.0.1", "JUnit");

        assertNotNull(raw);
        assertTrue(tokenRepository.findByTokenHash(tokenHasher.hash(raw)).isPresent());
        assertTrue(tokenRepository.findByTokenHash(raw).isEmpty(), "Token em claro nao deve ser persistido");
    }

    @Test
    void tokenExpiradoNaoPodeSerUsado() {
        String raw = service.createResetToken(user.getEmail(), "127.0.0.1", "JUnit");
        PasswordResetToken token = tokenRepository.findByTokenHash(tokenHasher.hash(raw)).orElseThrow();
        token.setExpiresAt(Instant.now().minus(1, ChronoUnit.MINUTES));
        tokenRepository.saveAndFlush(token);

        assertThrows(IllegalStateException.class,
                () -> service.resetPassword(raw, NEW_PASSWORD, "127.0.0.1", "JUnit"));
    }

    @Test
    void tokenValidoEDeUsoUnico() {
        String raw = service.createResetToken(user.getEmail(), "127.0.0.1", "JUnit");

        assertDoesNotThrow(() -> service.resetPassword(raw, NEW_PASSWORD, "127.0.0.1", "JUnit"));
        assertThrows(IllegalStateException.class,
                () -> service.resetPassword(raw, NEW_PASSWORD, "127.0.0.1", "JUnit"));
    }

    @Test
    void concorrenciaNaoPermiteDuploUsoDoMesmoToken() throws Exception {
        String raw = service.createResetToken(user.getEmail(), "127.0.0.1", "JUnit");
        int threads = 4;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger successes = new AtomicInteger();
        AtomicInteger failures = new AtomicInteger();

        try {
            for (int i = 0; i < threads; i++) {
                pool.submit(() -> {
                    start.await();
                    try {
                        service.resetPassword(raw, NEW_PASSWORD, "127.0.0.1", "JUnit-thread");
                        successes.incrementAndGet();
                    } catch (Exception e) {
                        failures.incrementAndGet();
                    }
                    return null;
                });
            }
            start.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }

        assertEquals(1, successes.get(), "Exatamente uma requisição deve consumir o token");
        assertEquals(threads - 1, failures.get());
    }

    @Test
    void politicaDeSenhaEImpedeReutilizacaoDaAtual() {
        String raw = service.createResetToken(user.getEmail(), "127.0.0.1", "JUnit");

        assertTrue(passwordPolicy.violations("senha123").size() > 0);
        assertThrows(IllegalArgumentException.class,
                () -> service.resetPassword(raw, "senha123", "127.0.0.1", "JUnit"));

        // O token continua utilizável quando a validação da política falha.
        assertDoesNotThrow(() -> service.resetPassword(raw, NEW_PASSWORD, "127.0.0.1", "JUnit"));
        String raw2 = service.createResetToken(user.getEmail(), "127.0.0.1", "JUnit");
        assertThrows(IllegalArgumentException.class,
                () -> service.resetPassword(raw2, NEW_PASSWORD, "127.0.0.1", "JUnit"));
    }

    @Test
    void emailInexistenteNaoRevelaEnumeracao() {
        long before = tokenRepository.count();
        assertNull(service.createResetToken("inexistente-" + UUID.randomUUID() + "@faculdade.edu.br",
                "127.0.0.1", "JUnit"));
        assertEquals(before, tokenRepository.count(), "Nenhum token deve ser criado para e-mail inexistente");
    }

    @Test
    void novaSolicitacaoRevogaTokenAnterior() {
        String first = service.createResetToken(user.getEmail(), "127.0.0.1", "JUnit");
        String second = service.createResetToken(user.getEmail(), "127.0.0.1", "JUnit");

        assertFalse(service.isTokenUsable(first));
        assertTrue(service.isTokenUsable(second));
    }
}
