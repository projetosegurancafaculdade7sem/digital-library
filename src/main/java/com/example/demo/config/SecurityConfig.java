package com.example.demo.config;

import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.EmailNormalizer;
import com.example.demo.security.LoginAuthenticationFailureHandler;
import com.example.demo.security.LoginAuthenticationSuccessHandler;
import com.example.demo.security.RateLimitingFilter;
import com.example.demo.security.TwoFactorEnforcementFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Cadeia de filtros HTTP. O segundo fator e exigido pelo {@link TwoFactorEnforcementFilter}
 * (item 1 do parecer) e o painel de auditoria exige ROLE_ADMIN explicito (item 5).
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final RateLimitingFilter rateLimitingFilter;
    private final TwoFactorEnforcementFilter twoFactorEnforcementFilter;
    private final UserRepository userRepository;
    private final LoginAuthenticationSuccessHandler successHandler;
    private final LoginAuthenticationFailureHandler failureHandler;

    @Value("${security.admin.emails:}")
    private String adminEmails;

    @Value("${server.ssl.enabled:false}")
    private boolean sslEnabled;

    public SecurityConfig(RateLimitingFilter rateLimitingFilter,
                          TwoFactorEnforcementFilter twoFactorEnforcementFilter,
                          UserRepository userRepository,
                          LoginAuthenticationSuccessHandler successHandler,
                          LoginAuthenticationFailureHandler failureHandler) {
        this.rateLimitingFilter = rateLimitingFilter;
        this.twoFactorEnforcementFilter = twoFactorEnforcementFilter;
        this.userRepository = userRepository;
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        Set<String> admins = Arrays.stream(adminEmails.split(","))
                .map(EmailNormalizer::normalize)
                .filter(email -> !email.isEmpty())
                .collect(Collectors.toSet());

        return username -> userRepository.findByLoginEmail(username)
                .map(user -> {
                    unlockIfExpired(user);
                    String role = normalizeRole(user, admins);
                    return org.springframework.security.core.userdetails.User.builder()
                            .username(user.getEmail())
                            .password(user.getPasswordHash())
                            .roles(role)
                            .accountLocked(!user.isAccountNonLocked())
                            .disabled(user.isConsentRevoked())
                            .build();
                })
                .orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado"));
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   SessionRegistry sessionRegistry) throws Exception {
        http
                .addFilterBefore(rateLimitingFilter,
                        org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class)
                // Executado antes da autorizacao: bloqueia bypass de 2FA mesmo em rotas ADMIN.
                .addFilterBefore(twoFactorEnforcementFilter, AuthorizationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/", "/css/**", "/js/**", "/images/**", "/webjars/**", "/favicon.ico",
                                "/login", "/register", "/forgot-password", "/reset-password", "/error"
                        ).permitAll()
                        .requestMatchers("/login-2fa").authenticated()
                        .requestMatchers("/admin/audit/**").hasRole("ADMIN")
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
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .sessionFixation().migrateSession()
                        .maximumSessions(1)
                        .sessionRegistry(sessionRegistry)
                        .expiredUrl("/login?expired=true")
                )
                .headers(headers -> headers
                        .frameOptions(frame -> frame.deny())
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                // O Bootstrap e os ícones são servidos pelo jsDelivr; sem essas origens
                                // o navegador bloqueava CSS/JS/fontes e todas as telas ficavam sem estilo.
                                "default-src 'self'; "
                                        + "script-src 'self' https://cdn.jsdelivr.net; "
                                        + "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                                        + "font-src 'self' https://cdn.jsdelivr.net; "
                                        + "img-src 'self' data:; object-src 'none'; base-uri 'self'; "
                                        + "frame-ancestors 'none'"))
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31_536_000L))
                );

        if (sslEnabled) {
            http.redirectToHttps(Customizer.withDefaults());
        }

        return http.build();
    }

    private void unlockIfExpired(User user) {
        if (!user.isAccountNonLocked()
                && user.getLockedUntil() != null
                && Instant.now().isAfter(user.getLockedUntil())) {
            user.setAccountNonLocked(true);
            user.setFailedLoginAttempts(0);
            user.setLockedUntil(null);
            userRepository.save(user);
        }
    }

    private String normalizeRole(User user, Set<String> admins) {
        // Comparação exata com o e-mail gravado: contas antigas com variação de maiúsculas
        // (ex.: "Admin@...") não herdam o papel de administrador.
        String email = user.getEmail() == null ? "" : user.getEmail();
        if (admins.contains(email)) {
            return "ADMIN";
        }
        String role = user.getRole() == null ? "" : user.getRole();
        String normalized = role.startsWith("ROLE_") ? role.substring(5) : role;
        return normalized.isBlank() ? "USER" : normalized;
    }
}
