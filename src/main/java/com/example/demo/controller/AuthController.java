package com.example.demo.controller;

import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

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

        // 1. Verifica se o e-mail já existe
        if (userRepository.findByEmail(email).isPresent()) {
            model.addAttribute("error", "Este e-mail já está cadastrado no sistema.");
            return "auth/register";
        }

        // 2. Validação básica de senha
        if (password == null || password.length() < 8) {
            model.addAttribute("error", "A senha deve conter no mínimo 8 caracteres.");
            return "auth/register";
        }

        // 3. Criptografa a senha com Argon2id
        String hashedPassword = passwordEncoder.encode(password);

        // 4. Cria e popula o seu objeto User existente
        User user = new User();
        user.setName(name);
        user.setEmail(email);
        user.setPasswordHash(hashedPassword); // se o seu campo se chamar setPassword(), altere aqui

        userRepository.save(user);

        System.out.println(">>> [NOVO CADASTRO] Usuário cadastrado: " + email);

        // 5. Redireciona para o login com mensagem de sucesso
        return "redirect:/login?registered=true";
    }

    @GetMapping("/forgot-password")
    public String forgotPasswordPage() {
        return "auth/forgot-password";
    }

    @GetMapping("/login-2fa")
    public String twoFactorPage() {
        return "auth/two-factor";
    }
}