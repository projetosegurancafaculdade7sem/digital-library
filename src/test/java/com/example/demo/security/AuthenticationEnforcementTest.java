package com.example.demo.security;

import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Evidências de bypass, RBAC do painel, expiração e logout (item 1 do parecer). */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthenticationEnforcementTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private UserRepository userRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    private String userEmail;
    private String adminEmail;

    @BeforeEach
    void setUp() {
        userEmail = "user-" + UUID.randomUUID() + "@faculdade.edu.br";
        adminEmail = "admin-" + UUID.randomUUID() + "@faculdade.edu.br";
        saveUser(userEmail, "ROLE_USER");
        saveUser(adminEmail, "ROLE_ADMIN");
    }

    private void saveUser(String email, String role) {
        User user = User.builder()
                .name("Usuario Teste")
                .email(email)
                .passwordHash(passwordEncoder.encode("SenhaAtual@2026"))
                .passwordSalt("salt-teste")
                .twoFactorSecret("JBSWY3DPEHPK3PXP")
                .twoFactorEnabled(true)
                .role(role)
                .build();
        userRepository.saveAndFlush(user);
    }

    @Test
    void bypassSemSegundoFatorEBlockadoEmRotasSensiveis() throws Exception {
        mockMvc.perform(get("/dashboard").with(user(userEmail).roles("USER")))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login-2fa"));

        mockMvc.perform(get("/privacy/my-data").with(user(userEmail).roles("USER")))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login-2fa"));

        mockMvc.perform(post("/privacy/consent/revoke").with(user(userEmail).roles("USER")).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login-2fa"));

        mockMvc.perform(get("/admin/audit/analyze").with(user(adminEmail).roles("ADMIN")))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login-2fa"));
    }

    @Test
    void painelDeAuditoriaExigeAdminMesmoComSegundoFator() throws Exception {
        mockMvc.perform(get("/admin/audit/analyze")
                        .sessionAttr("2FA_VERIFIED", true)
                        .with(user(userEmail).roles("USER")))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/admin/audit/analyze")
                        .sessionAttr("2FA_VERIFIED", true)
                        .with(user(adminEmail).roles("ADMIN")))
                .andExpect(status().isOk());

        mockMvc.perform(get("/admin/audit/analyze.json")
                        .sessionAttr("2FA_VERIFIED", true)
                        .with(user(adminEmail).roles("ADMIN")))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "user-teste", roles = "USER")
    void sessaoExpiradaOuSemFlagNaoPassaDoFiltro() throws Exception {
        // Apos expiracao/invalidacao o atributo 2FA_VERIFIED nao sobrevive na nova sessao.
        MockHttpSession renewedSession = new MockHttpSession();
        renewedSession.setAttribute("2FA_VERIFIED", Boolean.FALSE);

        mockMvc.perform(get("/dashboard").session(renewedSession))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login-2fa"));
    }

    @Test
    void logoutInvalidaSessaoEFlagDoSegundoFator() throws Exception {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("2FA_VERIFIED", true);

        mockMvc.perform(post("/logout").session(session).with(csrf()))
                .andExpect(status().is3xxRedirection());

        assertTrue(session.isInvalid(), "A sessao deve ser invalidada no logout");
    }
}
