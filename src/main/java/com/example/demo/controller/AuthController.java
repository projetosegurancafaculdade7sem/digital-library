package com.example.demo.controller;

import com.example.demo.model.PasswordResetToken;
import com.example.demo.model.User;
import com.example.demo.repository.PasswordResetTokenRepository;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.AuditService;
import com.example.demo.service.MailService;
import com.example.demo.service.PasswordResetService;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Optional;

@Controller
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecureRandom secureRandom = new SecureRandom();
    private final PasswordResetService passwordResetService;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final MailService mailService;
    private final AuditService auditService;

    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder, PasswordResetService passwordResetService, PasswordResetTokenRepository passwordResetTokenRepository, MailService mailService, AuditService auditService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordResetService = passwordResetService;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.mailService = mailService;
        this.auditService = auditService;
    }

    @GetMapping("/login")
    public String loginPage() {
        return "auth/login";
    }



    // TELA E PROCESSAMENTO DE CADASTRO


    @GetMapping("/register")
    public String registerPage() {
        return "auth/register";
    }

    @PostMapping("/register")
    public String registerUser(@RequestParam("name") String name,
                               @RequestParam("email") String email,
                               @RequestParam("password") String password,
                               Model model) {

        try{
        if (userRepository.findByEmail(email).isPresent()) {
            model.addAttribute("error", "Este e-mail já está cadastrado no sistema.");

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
            System.out.println(" USUÁRIO REGISTRADO COM SUCESSO: " + email);

            return "redirect:/login?registered=true";
        } }catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("errorMessage", "Erro ao salvar no banco: " + e.getMessage());

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
    public String processForgotPassword(@RequestParam("email") String email,
                                        jakarta.servlet.http.HttpServletRequest request) {
        // 1️⃣Captura dados do cliente (IP e User‑Agent) para auditoria e token
        String clientIp   = request.getRemoteAddr();
        String userAgent  = request.getHeader("User-Agent");

        // Gera o token (null → e‑mail inexistente)
        String token = passwordResetService.createResetToken(email, clientIp, userAgent);

        // Se houver token válido, envia o e‑mail de recuperação
        if (token != null) {
            mailService.sendPasswordResetEmail(email, token);
        }

        // Registra a tentativa (independente de sucesso)
        auditService.logEvent(null, "PASSWORD_RESET_REQUEST", clientIp, userAgent);

        // Redireciona – a página pode exibir a mensagem “seu e‑mail recebeu instruções”
        return "redirect:/forgot-password?sent=true";
    }


    @GetMapping("/reset-password")
    public String resetPasswordPage(@RequestParam("token") String token, Model model) {
        // Obter o email ou o ID do usuário associado ao token para exibir na página
        Optional<PasswordResetToken> tokenOpt = passwordResetTokenRepository.findByToken(token);
        if (tokenOpt.isEmpty() || tokenOpt.get().isUsed() || tokenOpt.get().getExpiresAt().isBefore(Instant.now())) {
             return "redirect:/login?error=token-invalido";
        }
        
        User user = userRepository.findById(tokenOpt.get().getUserID())
                .orElseThrow(() -> new IllegalArgumentException("Usuário não encontrado"));

        model.addAttribute("token", token);
        model.addAttribute("email", user.getEmail());
        return "auth/reset-password";
    }

    @PostMapping("/reset-password")
    public String processResetPassword(@RequestParam("token") String token,
                                       @RequestParam("password") String newPassword,
                                       jakarta.servlet.http.HttpServletRequest request,
                                       Model model) {

        String clientIp = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        if (newPassword == null || newPassword.length() < 8) {
            model.addAttribute("error", "A senha deve conter no mínimo 8 caracteres.");
            return "auth/reset-password";
        }
        
        try {
            passwordResetService.resetPassword(token, newPassword, clientIp, userAgent);
            auditService.logEvent(null, "PASSWORD_RESET_SUCCESS", clientIp, userAgent);
            return "redirect:/login?resetSuccess=true";
        } catch (Exception e) {
            auditService.logEvent(null, "PASSWORD_RESET_FAILURE", clientIp, userAgent);
            model.addAttribute("error", e.getMessage());
            return "auth/reset-password";
        }
    }

    @GetMapping("/login-2fa")
    public String twoFactorPage(HttpSession session, Authentication authentication, Model model) {
        int codeInt = secureRandom.nextInt(1_000_000);
        String code2FA = String.format("%06d", codeInt);

        session.setAttribute("2FA_CODE", code2FA);
        session.setAttribute("2FA_EXPIRY", LocalDateTime.now().plusMinutes(5));

        String username = (authentication != null) ? authentication.getName() : "Usuário";


        System.out.println("CÓDIGO 2FA GERADO");
        System.out.println(" Usuário: " + username);
        System.out.println("CÓDIGO DE ACESSO: " + code2FA);
        System.out.println("Válido por 5 minutos.");
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