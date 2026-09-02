package com.example.demo.controller;

import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;

@Controller
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecureRandom secureRandom = new SecureRandom();

    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/login")
    public String loginPage() {
        return "auth/login";
    }

    @GetMapping("/register")
    public String registerPage() {
        return "auth/register";
    }

    @PostMapping("/register")
    public String registerUser(@RequestParam("name") String name,
                               @RequestParam("email") String email,
                               @RequestParam("password") String password,
                               Model model) {

        if (userRepository.findByEmail(email).isPresent()) {
            model.addAttribute("error", "Este e-mail já está cadastrado no sistema.");
            return "auth/register";
        }

        if (password == null || password.length() < 8) {
            model.addAttribute("error", "A senha deve conter no mínimo 8 caracteres.");
            return "auth/register";
        }

        String hashedPassword = passwordEncoder.encode(password);

        User user = new User();
        user.setName(name);
        user.setEmail(email);
        user.setPasswordHash(hashedPassword);

        userRepository.save(user);

        return "redirect:/login?registered=true";
    }

    @GetMapping("/forgot-password")
    public String forgotPasswordPage() {
        return "auth/forgot-password";
    }

    @PostMapping("/forgot-password")
    public String processForgotPassword(@RequestParam("email") String email) {
        String resetLink = "http://localhost:8080/reset-password?email=" + email;

        System.out.println("=================================================");
        System.out.println(">>> [SIMULAÇÃO DE E-MAIL DE RECUPERAÇÃO]");
        System.out.println(">>> Destinatário: " + email);
        System.out.println(">>> Clique no link para redefinir: " + resetLink);
        System.out.println("=================================================");

        return "redirect:/forgot-password?sent=true";
    }

    @GetMapping("/reset-password")
    public String resetPasswordPage(@RequestParam("email") String email, Model model) {
        model.addAttribute("email", email);
        return "auth/reset-password";
    }

    @PostMapping("/reset-password")
    public String processResetPassword(@RequestParam("email") String email,
                                       @RequestParam("password") String newPassword,
                                       Model model) {

        if (newPassword == null || newPassword.length() < 8) {
            model.addAttribute("email", email);
            model.addAttribute("error", "A senha deve conter no mínimo 8 caracteres.");
            return "auth/reset-password";
        }

        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            user.setPasswordHash(passwordEncoder.encode(newPassword));
            userRepository.save(user);
            System.out.println(">>> [SENHA ATUALIZADA] Sucesso para: " + email);
        }

        return "redirect:/login?resetSuccess=true";
    }

    @GetMapping("/login-2fa")
    public String twoFactorPage(HttpSession session, Authentication authentication, Model model) {
        int codeInt = secureRandom.nextInt(1_000_000);
        String code2FA = String.format("%06d", codeInt);

        session.setAttribute("2FA_CODE", code2FA);
        session.setAttribute("2FA_EXPIRY", LocalDateTime.now().plusMinutes(5));

        String username = (authentication != null) ? authentication.getName() : "Usuário";

        System.out.println("=================================================");
        System.out.println(">>> [CÓDIGO 2FA GERADO]");
        System.out.println(">>> Usuário: " + username);
        System.out.println(">>> CÓDIGO DE ACESSO: " + code2FA);
        System.out.println(">>> Válido por 5 minutos.");
        System.out.println("=================================================");

        return "auth/two-factor";
    }

    @PostMapping("/login-2fa")
    public String verifyTwoFactor(@RequestParam("code") String inputCode,
                                  HttpSession session,
                                  Model model) {

        String expectedCode = (String) session.getAttribute("2FA_CODE");
        LocalDateTime expiry = (LocalDateTime) session.getAttribute("2FA_EXPIRY");

        if (expectedCode == null || expiry == null || LocalDateTime.now().isAfter(expiry)) {
            model.addAttribute("error", "O código expirou. Faça login novamente.");
            return "auth/two-factor";
        }

        if (!expectedCode.equals(inputCode.trim())) {
            model.addAttribute("error", "Código de verificação incorreto. Tente novamente.");
            return "auth/two-factor";
        }

        session.removeAttribute("2FA_CODE");
        session.removeAttribute("2FA_EXPIRY");
        session.setAttribute("2FA_VERIFIED", true);

        return "redirect:/dashboard";
    }

    @GetMapping("/dashboard")
    public String dashboardPage(HttpSession session, Authentication authentication, Model model) {
        Boolean is2FAVerified = (Boolean) session.getAttribute("2FA_VERIFIED");
        if (is2FAVerified == null || !is2FAVerified) {
            return "redirect:/login-2fa";
        }

        String userEmail = (authentication != null) ? authentication.getName() : "Usuário Acadêmico";
        model.addAttribute("username", userEmail);

        return "dashboard";
    }
}