package com.example.demo.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.File;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;

/**
 * Falha o boot de producao se TLS, chaves ou schema estiverem mal configurados
 * (itens 3 e 6 do parecer). Nao imprime nenhum valor sensivel.
 */
@Component
@Profile("!test & !dast")
public class StartupSecurityValidator implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(StartupSecurityValidator.class);

    private final boolean tlsRequired;
    private final boolean sslEnabled;
    private final String keyStore;
    private final String keyStorePassword;
    private final String datasourceUrl;
    private final boolean datasourceSslRequired;
    private final String ddlAuto;
    private final String encryptionKey;
    private final String hmacKey;
    private final String mailHost;
    private final String mailUsername;
    private final String mailPassword;
    private final String resetBaseUrl;

    public StartupSecurityValidator(
            @Value("${security.tls.require:true}") boolean tlsRequired,
            @Value("${server.ssl.enabled:true}") boolean sslEnabled,
            @Value("${server.ssl.key-store:}") String keyStore,
            @Value("${server.ssl.key-store-password:}") String keyStorePassword,
            @Value("${spring.datasource.url:}") String datasourceUrl,
            @Value("${security.datasource.ssl-required:true}") boolean datasourceSslRequired,
            @Value("${spring.jpa.hibernate.ddl-auto:validate}") String ddlAuto,
            @Value("${security.encryption.key-base64:}") String encryptionKey,
            @Value("${security.audit.hmac-key-base64:}") String hmacKey,
            @Value("${spring.mail.host:}") String mailHost,
            @Value("${spring.mail.username:}") String mailUsername,
            @Value("${spring.mail.password:}") String mailPassword,
            @Value("${mail.reset.base-url:}") String resetBaseUrl) {
        this.tlsRequired = tlsRequired;
        this.sslEnabled = sslEnabled;
        this.keyStore = keyStore;
        this.keyStorePassword = keyStorePassword;
        this.datasourceUrl = datasourceUrl;
        this.datasourceSslRequired = datasourceSslRequired;
        this.ddlAuto = ddlAuto;
        this.encryptionKey = encryptionKey;
        this.hmacKey = hmacKey;
        this.mailHost = mailHost;
        this.mailUsername = mailUsername;
        this.mailPassword = mailPassword;
        this.resetBaseUrl = resetBaseUrl;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (tlsRequired) {
            require(sslEnabled, "TLS obrigatorio: defina SERVER_SSL_ENABLED=true");
            requirePresent(keyStore, "SERVER_SSL_KEY_STORE");
            requirePresent(keyStorePassword, "SERVER_SSL_KEY_STORE_PASSWORD");
            require(!isWeakSecret(keyStorePassword), "Senha do keystore fraca/conhecida — rotacione o certificado");
            require(keyStoreExists(), "Keystore TLS nao encontrado: " + keyStore);
            require(resetBaseUrl.startsWith("https://"), "MAIL_RESET_BASE_URL deve usar HTTPS");
        }

        requirePresent(encryptionKey, "SECURITY_ENCRYPTION_KEY_BASE64");
        requirePresent(hmacKey, "SECURITY_AUDIT_HMAC_KEY_BASE64");
        byte[] aes = decode(encryptionKey, "SECURITY_ENCRYPTION_KEY_BASE64", 32);
        byte[] hmac = decode(hmacKey, "SECURITY_AUDIT_HMAC_KEY_BASE64", 32);
        require(!Arrays.equals(aes, hmac), "As chaves AES e HMAC de auditoria devem ser distintas");

        if (datasourceSslRequired) {
            require(datasourceUrl.toLowerCase(Locale.ROOT).contains("sslmode=require"),
                    "A URL do PostgreSQL deve exigir sslmode=require");
        }

        require(Arrays.asList("validate", "none").contains(ddlAuto.toLowerCase(Locale.ROOT)),
                "spring.jpa.hibernate.ddl-auto deve ser validate ou none em producao");

        requirePresent(mailHost, "SPRING_MAIL_HOST");
        requirePresent(mailUsername, "SPRING_MAIL_USERNAME");
        requirePresent(mailPassword, "SPRING_MAIL_PASSWORD");
        require(!isWeakSecret(mailPassword), "Credencial SMTP fraca/conhecida — rotacione no provedor");

        log.info("[SECURITY-CHECK] TLS={}, DB_SSL={}, ddl-auto={}, chaves distintas e tamanhos validos",
                sslEnabled, datasourceSslRequired, ddlAuto);
    }

    private boolean keyStoreExists() {
        if (keyStore.startsWith("classpath:")) {
            return new ClassPathResource(keyStore.substring("classpath:".length())).exists();
        }
        return new File(keyStore).isFile();
    }

    private byte[] decode(String value, String name, int expectedLength) {
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            require(decoded.length == expectedLength,
                    name + " deve decodificar para " + expectedLength + " bytes");
            return decoded;
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(name + " nao e Base64 valido", e);
        }
    }

    private boolean isWeakSecret(String value) {
        String normalized = value.toLowerCase(Locale.ROOT);
        return normalized.contains("changeit") || normalized.contains("change-me")
                || normalized.contains("dummy") || normalized.contains("root")
                || normalized.equals("password") || normalized.equals("123456");
    }

    private void requirePresent(String value, String name) {
        require(value != null && !value.isBlank(), "Variavel obrigatoria ausente: " + name);
    }

    private void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException("[SECURITY-CHECK] " + message);
        }
    }
}
