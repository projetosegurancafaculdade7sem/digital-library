package com.example.demo.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StartupSecurityValidatorTest {

    private static final String AES_KEY = "ZiMgxRPJ7W+3baJZGdHMKLU5AenG3EPbiA1p64asM6Q=";
    private static final String HMAC_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

    private StartupSecurityValidator validatorWith(Map<String, Object> properties) {
        MockEnvironment env = new MockEnvironment();
        properties.forEach((key, value) -> env.setProperty(key, String.valueOf(value)));
        StartupSecurityValidator validator = new StartupSecurityValidator();
        validator.setEnvironment(env);
        return validator;
    }

    private Map<String, Object> validProxyTlsConfig() {
        Map<String, Object> props = new HashMap<>();
        props.put("security.tls.require", false);
        props.put("server.ssl.enabled", false);
        props.put("security.datasource.ssl-required", true);
        props.put("spring.datasource.url",
                "jdbc:postgresql://db.example.com:6543/postgres?sslmode=require");
        props.put("spring.jpa.hibernate.ddl-auto", "validate");
        props.put("security.encryption.key-base64", AES_KEY);
        props.put("security.audit.hmac-key-base64", HMAC_KEY);
        props.put("spring.mail.host", "smtp.example.com");
        props.put("spring.mail.username", "usuario@example.com");
        props.put("spring.mail.password", "SenhaForte@2026!");
        props.put("mail.from", "no-reply@example.com");
        props.put("mail.reset.base-url", "https://example.com/reset-password?token=");
        return props;
    }

    @Test
    void aceitaConfiguracaoValidaComTlsTerminadoNoProxy() {
        assertDoesNotThrow(() -> validatorWith(validProxyTlsConfig()).postProcessBeanFactory(null));
    }

    @Test
    void reportaTodasAsVariaveisAusentesEmUmaUnicaMensagem() {
        Map<String, Object> props = new HashMap<>();
        props.put("security.tls.require", false);
        props.put("server.ssl.enabled", false);

        IllegalStateException error = assertThrows(IllegalStateException.class,
                () -> validatorWith(props).postProcessBeanFactory(null));

        String message = error.getMessage();
        assertTrue(message.contains("SPRING_MAIL_HOST"), message);
        assertTrue(message.contains("SPRING_DATASOURCE_URL"), message);
        assertTrue(message.contains("SECURITY_ENCRYPTION_KEY_BASE64"), message);
        assertTrue(message.contains("SECURITY_AUDIT_HMAC_KEY_BASE64"), message);
        assertTrue(message.contains("MAIL_FROM"), message);
        assertTrue(message.contains("MAIL_RESET_BASE_URL"), message);
    }

    @Test
    void exigeHttpsNoLinkDeResetMesmoSemTlsLocal() {
        Map<String, Object> props = validProxyTlsConfig();
        props.put("mail.reset.base-url", "http://example.com/reset-password?token=");

        IllegalStateException error = assertThrows(IllegalStateException.class,
                () -> validatorWith(props).postProcessBeanFactory(null));
        assertTrue(error.getMessage().contains("MAIL_RESET_BASE_URL"));
    }
}
