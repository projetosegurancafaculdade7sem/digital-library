package com.example.demo.controller;

import com.example.demo.dto.request.LoginForm;
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Controller
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // Armazena temporariamente os tokens de recuperação: Map<Token, Email>
    private static final Map<String, String> resetTokenStore = new ConcurrentHashMap<>();

    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // ==========================================
    // TELA E PROCESSAMENTO DE LOGIN
    // ==========================================
    @GetMapping("/login")
    public String showLoginPage(@RequestParam(value = "error", required = false) String error,
                                @RequestParam(value = "logout", required = false) String logout,
                                @RequestParam(value = "expired", required = false) String expired,
                                @RequestParam(value = "registered", required = false) String registered,
                                @RequestParam(value = "reset", required = false) String reset,
                                Model model) {

        if (!model.containsAttribute("loginForm")) {
            model.addAttribute("loginForm", new LoginForm());
        }

        if (error != null) {
            model.addAttribute("errorMessage", "Credenciais inválidas ou conta bloqueada temporariamente.");
        }
        if (logout != null) {
            model.addAttribute("logoutMessage", "Sessão encerrada com sucesso.");
        }
        if (expired != null) {
            model.addAttribute("expiredMessage", "Sua sessão expirou por inatividade.");
        }
        if (registered != null) {
            model.addAttribute("registeredMessage", "Cadastro realizado com sucesso! Faça seu login.");
        }
        if (reset != null) {
            model.addAttribute("successMessage", "Senha alterada com sucesso! Faça login com a nova senha.");
        }

        return "auth/login";
    }

    // ==========================================
    // TELA E PROCESSAMENTO DE CADASTRO
    // ==========================================
    @GetMapping("/register")
    public String showRegisterPage() {
        return "auth/register";
    }

    @PostMapping("/register")
    public String handleRegister(@RequestParam("name") String name,
                                 @RequestParam("email") String email,
                                 @RequestParam("password") String password,
                                 Model model) {
        try {
            if (userRepository.findByEmail(email).isPresent()) {
                model.addAttribute("errorMessage", "Já existe um usuário cadastrado com este e-mail.");
                return "auth/register";
            }

            User newUser = new User();
            newUser.setName(name);
            newUser.setEmail(email);
            newUser.setPasswordHash(passwordEncoder.encode(password));
            newUser.setRole("ROLE_USER");
            newUser.setTwoFactorEnabled(false);
            newUser.setAccountNonLocked(true);
            newUser.setFailedLoginAttempts(0);
            newUser.setCreatedAt(Instant.now());

            userRepository.save(newUser);
            System.out.println(">>> USUÁRIO REGISTRADO COM SUCESSO: " + email);

            return "redirect:/login?registered=true";
        } catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("errorMessage", "Erro ao salvar no banco: " + e.getMessage());
            return "auth/register";
        }
    }

    // ==========================================
    // RECUPERAÇÃO DE SENHA (FORGOT PASSWORD)
    // ==========================================
    @GetMapping("/forgot-password")
    public String showForgotPasswordPage() {
        return "auth/forgot-password";
    }

    @PostMapping("/forgot-password")
    public String handleForgotPassword(@RequestParam("email") String email, Model model) {
        try {
            Optional<User> userOptional = userRepository.findByEmail(email);

            if (userOptional.isPresent()) {
                String resetToken = UUID.randomUUID().toString();
                resetTokenStore.put(resetToken, email);

                System.out.println("==================================================");
                System.out.println(">>> TOKEN DE REDEFINIÇÃO GERADO PARA: " + email);
                System.out.println(">>> LINK: http://localhost:8080/reset-password?token=" + resetToken);
                System.out.println("==================================================");
            }

            model.addAttribute("successMessage", "Se o e-mail estiver cadastrado, o link de recuperação foi enviado.");
            return "auth/forgot-password";
        } catch (Exception e) {
            model.addAttribute("errorMessage", "Erro ao processar solicitação: " + e.getMessage());
            return "auth/forgot-password";
        }
    }

    // ==========================================
    // REDEFINIÇÃO DE SENHA (RESET PASSWORD)
    // ==========================================
    @GetMapping("/reset-password")
    public String showResetPasswordPage(@RequestParam(value = "token", required = false) String token, Model model) {
        if (token == null || !resetTokenStore.containsKey(token)) {
            model.addAttribute("errorMessage", "Token inválido ou expirado.");
        }
        model.addAttribute("token", token);
        return "auth/reset-password";
    }

    @PostMapping("/reset-password")
    public String handleResetPassword(@RequestParam(value = "token", required = false) String token,
                                      @RequestParam("newPassword") String newPassword,
                                      Model model) {
        try {
            if (token == null || !resetTokenStore.containsKey(token)) {
                model.addAttribute("errorMessage", "Token de redefinição inválido ou expirado.");
                return "auth/reset-password";
            }

            String email = resetTokenStore.get(token);
            Optional<User> userOptional = userRepository.findByEmail(email);

            if (userOptional.isPresent()) {
                User user = userOptional.get();
                user.setPasswordHash(passwordEncoder.encode(newPassword));
                user.setUpdatedAt(Instant.now());
                userRepository.save(user);

                resetTokenStore.remove(token);
                System.out.println(">>> SENHA ATUALIZADA COM SUCESSO PARA: " + email);
            }

            return "redirect:/login?reset=true";
        } catch (Exception e) {
            model.addAttribute("errorMessage", "Erro ao redefinir senha: " + e.getMessage());
            return "auth/reset-password";
        }
    }

    // ==========================================
    // AUTENTICAÇÃO DE DOIS FATORES (2FA)
    // ==========================================
    @GetMapping("/login-2fa")
    public String show2faPage() {
        return "auth/two-factor";
    }
}