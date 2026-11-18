package com.example.demo.security;

import com.example.demo.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

/**
 * Exige o segundo fator em TODAS as rotas sensíveis (item 1 do parecer).
 *
 * <p>A verificação não fica mais espalhada pelo controller: depois que o Spring Security
 * autentica a senha, qualquer requisição autenticada que não seja pública e que não seja a
 * própria página de 2FA é redirecionada para {@code /login-2fa} até que o atributo de sessão
 * {@code 2FA_VERIFIED} seja verdedadeiro.</p>
 *
 * <p>Também aplica imediatamente a revogação de consentimento (item 4): se o titular revogou
 * a finalidade da conta, a sessão é invalidada e o login é bloqueado na origem.</p>
 */
@Component
public class TwoFactorEnforcementFilter extends OncePerRequestFilter {

    public static final String TWO_FA_ATTRIBUTE = "2FA_VERIFIED";

    private static final Set<String> PUBLIC_OR_2FA_PATHS = Set.of(
            "/", "/login", "/perform_login", "/register", "/forgot-password",
            "/reset-password", "/login-2fa", "/logout", "/error",
            "/css", "/js", "/images", "/webjars", "/favicon.ico"
    );

    private final UserRepository userRepository;

    public TwoFactorEnforcementFilter(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = normalizedPath(request);

        if (isPublicOrSecondFactorPath(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            filterChain.doFilter(request, response);
            return;
        }

        HttpSession session = request.getSession(false);
        if (session == null || !Boolean.TRUE.equals(session.getAttribute(TWO_FA_ATTRIBUTE))) {
            redirect(response, request.getContextPath() + "/login-2fa");
            return;
        }

        boolean consentRevoked = userRepository.findByEmail(authentication.getName())
                .map(user -> user.isConsentRevoked())
                .orElse(false);
        if (consentRevoked) {
            SecurityContextHolder.clearContext();
            session.invalidate();
            redirect(response, request.getContextPath() + "/login?consent-revoked=true");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void redirect(HttpServletResponse response, String target) throws IOException {
        response.sendRedirect(target);
    }

    private boolean isPublicOrSecondFactorPath(String path) {
        for (String allowed : PUBLIC_OR_2FA_PATHS) {
            if (path.equals(allowed) || path.startsWith(allowed + "/")) {
                return true;
            }
        }
        return false;
    }

    private String normalizedPath(HttpServletRequest request) {
        String path = request.getRequestURI();
        String context = request.getContextPath();
        if (context != null && !context.isBlank() && path.startsWith(context)) {
            path = path.substring(context.length());
        }
        if (path.isEmpty()) {
            path = "/";
        }
        return path;
    }
}
