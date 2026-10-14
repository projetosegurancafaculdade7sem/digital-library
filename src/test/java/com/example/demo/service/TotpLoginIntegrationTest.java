package com.example.demo.service;

import com.example.demo.dto.request.RegisterRequest;
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
@ActiveProfiles("test")
class TotpLoginIntegrationTest {

    @Autowired
    private UserService userService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private TwoFactorService twoFactorService;

    @Test
    @Transactional
    void registerThenVerifyCurrentTotpCode() throws Exception {
        RegisterRequest req = new RegisterRequest();
        req.setEmail("totp-test-" + System.currentTimeMillis() + "@faculdade.edu.br");
        req.setPassword("senha12345");
        req.setAcceptTerms(true);

        UserService.RegistrationResult result =
                userService.registerUser(req, "Teste TOTP", "127.0.0.1", "JUnit");

        User fromDb = userRepository.findByEmail(req.getEmail()).orElseThrow();
        String secret = fromDb.getTotpSecret();

        long bucket = Math.floorDiv(System.currentTimeMillis() / 1000, 30);
        String code = new dev.samstevens.totp.code.DefaultCodeGenerator(
                dev.samstevens.totp.code.HashingAlgorithm.SHA1, 6)
                .generate(secret, bucket);

        assertTrue(twoFactorService.verifyCode(secret, code),
                "Código gerado a partir do segredo persistido deve validar");
        assertTrue(twoFactorService.verifyCode(result.totpSecretPlaintext(), code),
                "Código deve validar também com o plaintext do cadastro");
    }
}
