package com.example.demo.security;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Criptografia de atributos sensíveis em repouso (req. 3.4–3.8).
 *
 * <ul>
 *   <li>Algoritmo: AES-256 / modo GCM (AEAD) — confidencialidade + integridade.</li>
 *   <li>IV: 12 bytes aleatórios (recomendação NIST SP 800-38D) por registro.</li>
 *   <li>Tag: 128 bits.</li>
 *   <li>Chave: 32 bytes, fornecida via {@code security.encryption.key-base64}
 *       (variável de ambiente / properties), nunca hardcoded no código-fonte.</li>
 * </ul>
 *
 * Justificativa: AES-GCM é amplamente aceito para dados em repouso; GCM evita
 * padding oracle e autentica o ciphertext. A chave permanece fora do repositório
 * em produção (env/secret manager).
 */
@Component
@Converter
public class AttributeEncryptor implements AttributeConverter<String, String> {

    private static final String AES = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    /** Instância gerenciada pelo Spring — usada quando o JPA instancia o converter. */
    private static volatile byte[] SHARED_KEY;

    private final byte[] secretKeyBytes;

    @Autowired
    public AttributeEncryptor(
            @Value("${security.encryption.key-base64}") String keyBase64) {
        this.secretKeyBytes = decodeKey(keyBase64);
        SHARED_KEY = this.secretKeyBytes;
    }

    /** Construtor sem args exigido pelo JPA caso a BeanContainer não injete o bean. */
    public AttributeEncryptor() {
        this.secretKeyBytes = SHARED_KEY;
    }

    private static byte[] decodeKey(String keyBase64) {
        byte[] decoded = Base64.getDecoder().decode(keyBase64);
        if (decoded.length != 32) {
            throw new IllegalStateException(
                    "security.encryption.key-base64 deve decodificar para exatamente 32 bytes (AES-256).");
        }
        return decoded;
    }

    private byte[] keyBytes() {
        if (secretKeyBytes != null) {
            return secretKeyBytes;
        }
        if (SHARED_KEY != null) {
            return SHARED_KEY;
        }
        throw new IllegalStateException("Chave de criptografia não inicializada.");
    }

    @Override
    public String convertToDatabaseColumn(String attribute) {
        if (attribute == null) {
            return null;
        }
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes(), AES);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

            byte[] cipherText = cipher.doFinal(attribute.getBytes(StandardCharsets.UTF_8));
            byte[] ciphertextWithIv = ByteBuffer.allocate(iv.length + cipherText.length)
                    .put(iv)
                    .put(cipherText)
                    .array();

            return Base64.getEncoder().encodeToString(ciphertextWithIv);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting attribute", e);
        }
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        if (dbData == null) {
            return null;
        }
        try {
            byte[] cipherTextWithIv = Base64.getDecoder().decode(dbData);
            ByteBuffer byteBuffer = ByteBuffer.wrap(cipherTextWithIv);

            byte[] iv = new byte[GCM_IV_LENGTH];
            byteBuffer.get(iv);

            byte[] cipherText = new byte[byteBuffer.remaining()];
            byteBuffer.get(cipherText);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes(), AES);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

            byte[] plainText = cipher.doFinal(cipherText);
            return new String(plainText, StandardCharsets.UTF_8);
        } catch (Exception e) {
            // Compatibilidade com valores legados em claro (migração).
            if (looksLikeTotpSecret(dbData)) {
                return dbData;
            }
            throw new RuntimeException("error while decrypting data", e);
        }
    }

    private boolean looksLikeTotpSecret(String value) {
        return value.matches("^[A-Z2-7]+=*$") && value.length() >= 16;
    }
}
