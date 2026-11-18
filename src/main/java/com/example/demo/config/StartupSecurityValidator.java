package com.example.demo.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.File;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Valida a configuracao de seguranca ANTES da criacao de qualquer bean
 * (itens 3 e 6 do parecer). Sendo um {@link BeanFactoryPostProcessor}, uma
 * variavel ausente gera uma unica mensagem clara, em vez de uma
 * PlaceholderResolutionException vinda da autoconfiguracao de mail.
 * Nao imprime nenhum valor sensivel.
 */
@Component
@Profile("!test & !dast")
public class StartupSecurityValidator implements BeanFactoryPostProcessor, EnvironmentAware {

    private static final Logger log = LoggerFactory.getLogger(StartupSecurityValidator.class);

    private ConfigurableEnvironment environment;

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = (ConfigurableEnvironment) environment;
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
        Map<String, String> errors = new LinkedHashMap<>();

        if (environment.getProperty("RENDER") != null) {
            log.warn("[SECURITY-CHECK] Render detectado: o TLS e terminado no proxy. "
                    + "Defina SERVER_SSL_ENABLED=false e SECURITY_TLS_REQUIRE=false.");
        }

        boolean tlsRequired = bool("security.tls.require", true);
        boolean sslEnabled = bool("server.ssl.enabled", true);
        boolean datasourceSslRequired = bool("security.datasource.ssl-required", true);
        String ddlAuto = prop("spring.jpa.hibernate.ddl-auto", "validate");

        if (tlsRequired) {
            require(errors, "SERVER_SSL_ENABLED", sslEnabled,
                    "TLS obrigatorio: defina SERVER_SSL_ENABLED=true");
            String keyStore = prop("server.ssl.key-store");
            String keyStorePassword = prop("server.ssl.key-store-password");
            if (keyStore.isBlank()) {
                errors.put("SERVER_SSL_KEY_STORE", "variavel obrigatoria ausente "
                        + "(ou defina SERVER_SSL_ENABLED=false / SECURITY_TLS_REQUIRE=false "
                        + "se o TLS e terminado no proxy)");
            }
            requirePresent(errors, "SERVER_SSL_KEY_STORE_PASSWORD", keyStorePassword);
            if (!keyStorePassword.isBlank() && isWeakSecret(keyStorePassword)) {
                errors.put("SERVER_SSL_KEY_STORE_PASSWORD", "senha do keystore fraca/conhecida — rotacione");
            }
            if (!keyStore.isBlank() && !keyStoreExists(keyStore)) {
                errors.put("SERVER_SSL_KEY_STORE", "keystore nao encontrado: " + keyStore);
            }
        }

        // O link de reset deve ser HTTPS mesmo quando o TLS e terminado no proxy (Render).
        String resetBaseUrl = prop("mail.reset.base-url");
        require(errors, "MAIL_RESET_BASE_URL", resetBaseUrl.startsWith("https://"),
                "deve usar HTTPS (ex.: https://seu-dominio.onrender.com/reset-password?token=)");

        String encryptionKey = prop("security.encryption.key-base64");
        String hmacKey = prop("security.audit.hmac-key-base64");
        requirePresent(errors, "SECURITY_ENCRYPTION_KEY_BASE64", encryptionKey);
        requirePresent(errors, "SECURITY_AUDIT_HMAC_KEY_BASE64", hmacKey);
        byte[] aes = decode(errors, "SECURITY_ENCRYPTION_KEY_BASE64", encryptionKey, 32);
        byte[] hmac = decode(errors, "SECURITY_AUDIT_HMAC_KEY_BASE64", hmacKey, 32);
        if (aes != null && hmac != null && Arrays.equals(aes, hmac)) {
            errors.put("SECURITY_AUDIT_HMAC_KEY_BASE64", "deve ser distinta da chave AES");
        }

        String datasourceUrl = prop("spring.datasource.url");
        requirePresent(errors, "SPRING_DATASOURCE_URL", datasourceUrl);
        if (datasourceSslRequired && !datasourceUrl.isBlank()
                && !datasourceUrl.toLowerCase(Locale.ROOT).contains("sslmode=require")) {
            errors.put("SPRING_DATASOURCE_URL", "deve exigir sslmode=require");
        }

        require(errors, "SPRING_JPA_DDL_AUTO",
                Arrays.asList("validate", "none").contains(ddlAuto.toLowerCase(Locale.ROOT)),
                "ddl-auto deve ser validate ou none em producao");

        String mailHost = prop("spring.mail.host");
        String mailUsername = prop("spring.mail.username");
        String mailPassword = prop("spring.mail.password");
        String mailFrom = prop("mail.from");
        requirePresent(errors, "SPRING_MAIL_HOST", mailHost);
        requirePresent(errors, "SPRING_MAIL_USERNAME", mailUsername);
        requirePresent(errors, "SPRING_MAIL_PASSWORD", mailPassword);
        requirePresent(errors, "MAIL_FROM", mailFrom);
        if (!mailPassword.isBlank() && isWeakSecret(mailPassword)) {
            errors.put("SPRING_MAIL_PASSWORD", "credencial SMTP fraca/conhecida — rotacione no provedor");
        }

        if (!errors.isEmpty()) {
            StringBuilder message = new StringBuilder("[SECURITY-CHECK] Configuracao de producao invalida:");
            errors.forEach((key, value) -> message.append("\n  - ").append(key).append(": ").append(value));
            throw new IllegalStateException(message.toString());
        }

        log.info("[SECURITY-CHECK] TLS local={}, DB_SSL={}, ddl-auto={}, chaves distintas e validas",
                sslEnabled, datasourceSslRequired, ddlAuto);
    }

    private String prop(String key) {
        return prop(key, "");
    }

    private String prop(String key, String defaultValue) {
        String value = environment.getProperty(key, defaultValue);
        return value == null ? defaultValue : value.trim();
    }

    private boolean bool(String key, boolean defaultValue) {
        String value = environment.getProperty(key);
        return value == null || value.isBlank() ? defaultValue : Boolean.parseBoolean(value.trim());
    }

    private boolean keyStoreExists(String keyStore) {
        if (keyStore.startsWith("classpath:")) {
            return new ClassPathResource(keyStore.substring("classpath:".length())).exists();
        }
        return new File(keyStore).isFile();
    }

    private byte[] decode(Map<String, String> errors, String name, String value, int expectedLength) {
        if (value.isBlank()) {
            return null;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            if (decoded.length != expectedLength) {
                errors.put(name, "deve decodificar para " + expectedLength + " bytes");
                return null;
            }
            return decoded;
        } catch (IllegalArgumentException e) {
            errors.put(name, "nao e Base64 valido");
            return null;
        }
    }

    private boolean isWeakSecret(String value) {
        String normalized = value.toLowerCase(Locale.ROOT);
        return normalized.contains("changeit") || normalized.contains("change-me")
                || normalized.contains("dummy") || normalized.contains("root")
                || normalized.equals("password") || normalized.equals("123456");
    }

    private void requirePresent(Map<String, String> errors, String key, String value) {
        require(errors, key, value != null && !value.isBlank(), "variavel obrigatoria ausente");
    }

    private void require(Map<String, String> errors, String key, boolean condition, String message) {
        if (!condition) {
            errors.put(key, message);
        }
    }
}
