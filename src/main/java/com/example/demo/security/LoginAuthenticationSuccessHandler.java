package com.example.demo.security;

import com.example.demo.repository.UserRepository;
import com.example.demo.service.AuditService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Integra o formLogin do Spring Security ao fluxo de auditoria e 2FA.
 * Após autenticação primária (senha), redireciona para validação TOTP.
 */
@Component
public class LoginAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final AuditService auditService;

    public LoginAuthenticationSuccessHandler(UserRepository userRepository, AuditService auditService) {
        this.userRepository = userRepository;
        this.auditService = auditService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        String email = authentication.getName();
        String ip = clientIp(request);
        String ua = request.getHeader("User-Agent");

        userRepository.findByEmail(email).ifPresent(user -> {
            user.setFailedLoginAttempts(0);
            userRepository.save(user);
            auditService.logEvent(user.getId(), "LOGIN_PRIMARY_SUCCESS", ip, ua);
        });

        HttpSession session = request.getSession(true);
        session.removeAttribute("2FA_VERIFIED");

        response.sendRedirect(request.getContextPath() + "/login-2fa");
    }

    private String clientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        if (xf == null || xf.isBlank()) {
            return request.getRemoteAddr();
        }
        return xf.split(",")[0].trim();
    }
}
