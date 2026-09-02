package com.example.demo.controller;

import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Optional;

@Controller
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

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
        // Simulação do envio: gera o link clicável direto no console do IntelliJ
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
    public String twoFactorPage() {
        return "auth/two-factor";
    }
}