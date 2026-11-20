package com.example.demo.service;

import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.HashingAlgorithm;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/** O mesmo código TOTP não pode ser usado duas vezes (anti-replay). */
@SpringBootTest
@ActiveProfiles("test")
class TotpReplayTest {

    private static final String SECRET = "JBSWY3DPEHPK3PXP";

    @Autowired private AuthService authService;
    @Autowired private UserRepository userRepository;

    private User createUser() {
        return userRepository.saveAndFlush(User.builder()
                .name("Replay")
                .email("replay-" + UUID.randomUUID() + "@faculdade.edu.br")
                .passwordHash("!")
                .twoFactorSecret(SECRET)
                .twoFactorEnabled(true)
                .build());
    }

    private static String codeFor(long step) throws Exception {
        return new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6).generate(SECRET, step);
    }

    private static long currentStep() {
        return Math.floorDiv(System.currentTimeMillis() / 1000, 30);
    }

    @Test
    void mesmoCodigoNaoEAceitoDuasVezes() throws Exception {
        User user = createUser();
        String code = codeFor(currentStep());

        assertTrue(authService.verify2FACode(user, code), "Primeiro uso deve ser aceito");
        assertFalse(authService.verify2FACode(user, code), "Reutilização deve ser recusada");

        User reloaded = userRepository.findById(user.getId()).orElseThrow();
        assertFalse(authService.verify2FACode(reloaded, code), "Recusa também com a entidade recarregada");
    }

    @Test
    void codigoDeJanelaAnteriorAoUltimoUsoERecusado() throws Exception {
        User user = createUser();
        long step = currentStep();

        assertTrue(authService.verify2FACode(user, codeFor(step)));
        assertFalse(authService.verify2FACode(user, codeFor(step - 1)),
                "Código de uma janela anterior à já usada não pode ser aceito");
    }

    @Test
    void codigoInvalidoNaoConsomeJanela() throws Exception {
        User user = createUser();
        assertFalse(authService.verify2FACode(user, "000000".equals(codeFor(currentStep())) ? "111111" : "000000"));
        assertTrue(authService.verify2FACode(user, codeFor(currentStep())));
    }
}
