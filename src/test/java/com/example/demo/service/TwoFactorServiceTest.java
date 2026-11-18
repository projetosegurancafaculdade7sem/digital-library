package com.example.demo.service;

import com.example.demo.security.AttributeEncryptor;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.HashingAlgorithm;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TwoFactorServiceTest {

    private static final String TEST_KEY_BASE64 = "ZiMgxRPJ7W+3baJZGdHMKLU5AenG3EPbiA1p64asM6Q=";

    @Test
    void generatedSecretRoundTripsThroughEncryptionAndVerifiesTotp() throws Exception {
        TwoFactorService totp = new TwoFactorService();
        AttributeEncryptor encryptor = new AttributeEncryptor(TEST_KEY_BASE64);

        String secret = totp.generateSecret();
        String encrypted = encryptor.convertToDatabaseColumn(secret);
        String decrypted = encryptor.convertToEntityAttribute(encrypted);

        assertEquals(secret, decrypted);

        long bucket = Math.floorDiv(System.currentTimeMillis() / 1000, 30);
        String code = new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6).generate(secret, bucket);

        assertTrue(totp.verifyCode(decrypted, code));
    }

    @Test
    void codigoForaDaJanelaDeTempoEInvalidado() throws Exception {
        TwoFactorService totp = new TwoFactorService();
        String secret = totp.generateSecret();
        long currentBucket = Math.floorDiv(System.currentTimeMillis() / 1000, 30);
        String expiredCode = new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6)
                .generate(secret, currentBucket - 10);

        assertFalse(totp.verifyCode(secret, expiredCode));
        assertFalse(totp.verifyCode(secret, "abc123"));
    }
}
