package com.example.demo.config;

import com.example.demo.repository.UserRepository;
import com.example.demo.security.LoginAuthenticationFailureHandler;
import com.example.demo.security.LoginAuthenticationSuccessHandler;
import com.example.demo.security.RateLimitingFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.time.Instant;

/**
 * Fluxo de autenticação (req. 1.7) — documentação formal:
 *
 * <pre>
 * 1. Cliente acessa /login (HTTPS — req. 3.1/3.2).
 * 2. POST /perform_login → Spring Security formLogin valida e-mail/senha (Argon2).
 * 3. RateLimitingFilter limita tentativas por IP nas rotas críticas (req. 1.11).
 * 4. Em falha: LoginAuthenticationFailureHandler incrementa tentativas e pode
 *    bloquear a conta por 15 min após 5 falhas (AuthService — req. 1.11).
 * 5. Em sucesso: LoginAuthenticationSuccessHandler registra LOGIN_PRIMARY_SUCCESS
 *    e redireciona para /login-2fa (req. 1.5/1.6).
 * 6. /login-2fa valida código TOTP (TwoFactorService) e só então define
 *    2FA_VERIFIED na sessão; dashboard exige esse atributo.
 * 7. Logout em /logout invalida a sessão e remove JSESSIONID (req. 1.10).
 * 8. Sessão: IF_REQUIRED, máximo 1 sessão por usuário, timeout configurado
 *    em server.servlet.session.timeout (padrão 15m — req. 1.9).
 * </pre>
 *
 * Justificativa dos parâmetros de sessão (req. 1.9 / 1.12):
 * timeout curto reduz janela de sequestro de sessão; maximumSessions(1) mitiga
 * reutilização simultânea de credenciais.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final RateLimitingFilter rateLimitingFilter;
    private final UserRepository userRepository;
    private final LoginAuthenticationSuccessHandler successHandler;
    private final LoginAuthenticationFailureHandler failureHandler;

    @Value("${server.servlet.session.timeout:15m}")
    private String sessionTimeout;

    @Value("${server.ssl.enabled:false}")
    private boolean sslEnabled;

    public SecurityConfig(RateLimitingFilter rateLimitingFilter,
                          UserRepository userRepository,
                          LoginAuthenticationSuccessHandler successHandler,
                          LoginAuthenticationFailureHandler failureHandler) {
        this.rateLimitingFilter = rateLimitingFilter;
        this.userRepository = userRepository;
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByEmail(username)
                .map(user -> {
                    if (!user.isAccountNonLocked()
                            && user.getLockedUntil() != null
                            && Instant.now().isAfter(user.getLockedUntil())) {
                        user.setAccountNonLocked(true);
                        user.setFailedLoginAttempts(0);
                        user.setLockedUntil(null);
                        userRepository.save(user);
                    }
                    return org.springframework.security.core.userdetails.User.builder()
                            .username(user.getEmail())
                            .password(user.getPasswordHash())
                            .roles("USER")
                            .accountLocked(!user.isAccountNonLocked())
                            .build();
                })
                .orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado: " + username));
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/css/**",
                                "/js/**",
                                "/images/**",
                                "/webjars/**",
                                "/favicon.ico",
                                "/login",
                                "/register",
                                "/forgot-password",
                                "/reset-password",
                                "/error"
                        ).permitAll()
                        .requestMatchers("/login-2fa").authenticated()
                        .requestMatchers("/privacy/**").authenticated()
                        .requestMatchers("/admin/audit/**").authenticated()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/perform_login")
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout=true")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )
                .sessionManagement(session -> session
                        // Timeout efetivo: server.servlet.session.timeout=${sessionTimeout}
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .maximumSessions(1)
                        .expiredUrl("/login?expired=true")
                );

        if (sslEnabled) {
            // Spring Security 7: requiresChannel foi removido (ChannelDecisionManager).
            // redirectToHttps + SSL no Tomcat atendem req. 3.1 / 3.2.
            http.redirectToHttps(Customizer.withDefaults());
        }

        return http.build();
    }
}
