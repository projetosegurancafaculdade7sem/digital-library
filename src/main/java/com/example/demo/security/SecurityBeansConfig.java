package com.example.demo.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Configuração do PasswordEncoder Argon2id (req. 1.1 / 1.2 / 1.12).
 *
 * <p><b>Justificativa técnica dos parâmetros</b> (alinhados a recomendações
 * OWASP Password Storage Cheat Sheet / RFC 9106 — Argon2id):</p>
 * <ul>
 *   <li>{@code saltLength=16}: 128 bits de entropia no salt; suficiente para
 *       unicidade por senha e resistir a rainbow tables.</li>
 *   <li>{@code hashLength=32}: 256 bits de saída; margem adequada contra
 *       colisões e ataques de pré-imagem no digest armazenado.</li>
 *   <li>{@code parallelism=1}: adequado a ambiente acadêmico/single-node;
 *       evita contenção excessiva de CPU em hosts compartilhados.</li>
 *   <li>{@code memory=65536} (64 MiB): custo de memória que dificulta ataques
 *       massivos em GPU/ASIC, mantendo login interativo aceitável.</li>
 *   <li>{@code iterations=3}: número de passes recomendado para Argon2id com
 *       ~64 MiB; equilíbrio entre segurança e latência de autenticação.</li>
 * </ul>
 * <p>O salt é gerado internamente pelo {@link Argon2PasswordEncoder} a cada
 * {@code encode()} e embutido na string PHC; o campo {@code passwordSalt} do
 * usuário armazena o mesmo salt de forma explícita (req. 1.3 / 1.4).</p>
 */
@Configuration
public class SecurityBeansConfig {

    @Value("${security.argon2.salt-length:16}")
    private int saltLength;

    @Value("${security.argon2.hash-length:32}")
    private int hashLength;

    @Value("${security.argon2.parallelism:1}")
    private int parallelism;

    @Value("${security.argon2.memory:65536}")
    private int memory;

    @Value("${security.argon2.iterations:3}")
    private int iterations;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Argon2PasswordEncoder(
                saltLength,
                hashLength,
                parallelism,
                memory,
                iterations
        );
    }
}
