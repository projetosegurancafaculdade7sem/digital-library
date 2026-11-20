package com.example.demo.security;

import com.example.demo.service.AuthService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Integra o bloqueio por tentativas (AuthService) ao fluxo padrão formLogin.
 */
@Component
public class LoginAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final AuthService authService;

    public LoginAuthenticationFailureHandler(AuthService authService) {
        this.authService = authService;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        String email = request.getParameter("username");
        String ip = clientIp(request);
        String ua = request.getHeader("User-Agent");

        boolean locked = exception instanceof LockedException
                || authService.registerFailedPasswordAttempt(email, ip, ua);

        String redirect = locked
                ? request.getContextPath() + "/login?locked=true"
                : request.getContextPath() + "/login?error=true";
        response.sendRedirect(redirect);
    }

    /**
     * O IP real ja vem resolvido pelo RemoteIpValve do Tomcat
     * (server.forward-headers-strategy=native), que so aceita X-Forwarded-For de proxies
     * confiaveis. Ler o cabecalho diretamente permitiria forjar o IP.
     */
    private String clientIp(HttpServletRequest request) {
        return request.getRemoteAddr();
    }
}
