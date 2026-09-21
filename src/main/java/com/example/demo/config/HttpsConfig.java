package com.example.demo.config;

import org.apache.catalina.connector.Connector;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * Adiciona conector HTTP que redireciona para HTTPS (req. 3.1 / 3.2),
 * sem substituir a factory padrão (preserva SSL auto-configurado).
 */
@Configuration
@Profile("!test")
public class HttpsConfig {

    @Value("${server.http.port:8080}")
    private int httpPort;

    @Value("${server.port:8443}")
    private int httpsPort;

    @Value("${server.ssl.enabled:false}")
    private boolean sslEnabled;

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> httpRedirectCustomizer() {
        return factory -> {
            if (sslEnabled) {
                Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
                connector.setScheme("http");
                connector.setPort(httpPort);
                connector.setSecure(false);
                connector.setRedirectPort(httpsPort);
                factory.addAdditionalConnectors(connector);
            }
        };
    }
}
