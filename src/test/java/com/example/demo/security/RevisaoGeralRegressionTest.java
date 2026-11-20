package com.example.demo.security;

import com.example.demo.dto.request.RegisterRequest;
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.SessionTerminationService;
import com.example.demo.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Regressões dos problemas encontrados na revisão geral. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RevisaoGeralRegressionTest {

    private static final String ADMIN_EMAIL = "admin@faculdade.edu.br"; // security.admin.emails

    @Autowired private MockMvc mockMvc;
    @Autowired private UserService userService;
    @Autowired private UserRepository userRepository;
    @Autowired private UserDetailsService userDetailsService;
    @Autowired private SessionRegistry sessionRegistry;
    @Autowired private SessionTerminationService sessionTerminationService;

    private static RequestPostProcessor fromIp(String ip) {
        return request -> {
            request.setRemoteAddr(ip);
            return request;
        };
    }

    private RegisterRequest registerRequest(String email) {
        RegisterRequest request = new RegisterRequest();
        request.setEmail(email);
        request.setPassword("SenhaForte@2026!");
        request.setAcceptTerms(true);
        return request;
    }

    @Test
    void cadastroNormalizaEmailEBloqueiaVariacaoDeMaiusculas() {
        String email = "aluno-" + UUID.randomUUID() + "@faculdade.edu.br";
        User created = userService.registerUser(registerRequest("  " + email.toUpperCase() + " "),
                "Aluno", "127.0.0.1", "JUnit").user();

        assertEquals(email, created.getEmail());
        assertThrows(IllegalArgumentException.class, () -> userService.registerUser(
                registerRequest(email.replace("aluno", "ALUNO")), "Outro", "127.0.0.1", "JUnit"));

        // Login aceita o e-mail digitado com maiúsculas.
        assertEquals(email, userDetailsService.loadUserByUsername(email.toUpperCase()).getUsername());
    }

    @Test
    void variacaoDeMaiusculasDoEmailAdminNaoRecebeRoleAdmin() {
        // Conta antiga gravada antes da normalização com uma variação do e-mail administrativo.
        userRepository.saveAndFlush(User.builder()
                .name("Impostor")
                .email("Admin@Faculdade.edu.br")
                .passwordHash("!")
                .role("ROLE_USER")
                .build());

        UserDetails details = userDetailsService.loadUserByUsername("Admin@Faculdade.edu.br");
        assertEquals("Admin@Faculdade.edu.br", details.getUsername());
        assertTrue(details.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .noneMatch("ROLE_ADMIN"::equals), "Variação de maiúsculas não pode virar ADMIN");
        assertFalse(userRepository.findByEmail(ADMIN_EMAIL).isPresent());
    }

    @Test
    void cspPermiteBootstrapDoJsDelivr() throws Exception {
        mockMvc.perform(get("/login").with(fromIp("10.1.1.1")))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy",
                        containsString("style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net")))
                .andExpect(header().string("Content-Security-Policy",
                        containsString("script-src 'self' https://cdn.jsdelivr.net")))
                .andExpect(header().string("Content-Security-Policy",
                        containsString("font-src 'self' https://cdn.jsdelivr.net")));
    }

    @Test
    void paginaInicialRedirecionaEmVezDe404() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/dashboard"));
    }

    @Test
    void xForwardedForForjadoNaoBurlaRateLimit() throws Exception {
        String ip = "10.77.0." + (int) (Math.random() * 200 + 1);
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(get("/forgot-password").with(fromIp(ip))
                            .header("X-Forwarded-For", "203.0.113." + i))
                    .andExpect(status().isOk());
        }
        mockMvc.perform(get("/forgot-password").with(fromIp(ip))
                        .header("X-Forwarded-For", "198.51.100.99"))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void exclusaoDeDadosEncerraSessao() throws Exception {
        String email = "excluir-" + UUID.randomUUID() + "@faculdade.edu.br";
        userRepository.saveAndFlush(User.builder()
                .name("Titular")
                .email(email)
                .passwordHash("!")
                .twoFactorSecret("JBSWY3DPEHPK3PXP")
                .twoFactorEnabled(true)
                .build());

        MockHttpSession session = new MockHttpSession();
        session.setAttribute("2FA_VERIFIED", true);

        mockMvc.perform(post("/privacy/delete").session(session).with(user(email).roles("USER")).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?deleted=true"));

        assertTrue(session.isInvalid(), "A sessão deve ser invalidada após a exclusão dos dados");
    }

    @Test
    void redefinicaoDeSenhaExpiraSessoesAtivas() {
        String email = "sessoes-" + UUID.randomUUID() + "@faculdade.edu.br";
        UserDetails principal = org.springframework.security.core.userdetails.User
                .withUsername(email).password("!").roles("USER").build();
        String sessionId = "sessao-" + UUID.randomUUID();
        sessionRegistry.registerNewSession(sessionId, principal);

        assertEquals(1, sessionTerminationService.expireAllSessions(email));
        SessionInformation info = sessionRegistry.getSessionInformation(sessionId);
        assertNotNull(info);
        assertTrue(info.isExpired());

        sessionRegistry.removeSessionInformation(sessionId);
    }
}
