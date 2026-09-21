package com.example.demo.controller;

import com.example.demo.dto.request.RegisterRequest;
import com.example.demo.model.PasswordResetToken;
import com.example.demo.model.User;
import com.example.demo.repository.PasswordResetTokenRepository;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.AuditService;
import com.example.demo.service.AuthService;
import com.example.demo.service.MailService;
import com.example.demo.service.PasswordResetService;
import com.example.demo.service.TwoFactorService;
import com.example.demo.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.Instant;
import java.util.Optional;

@Controller
public class AuthController {

    private final UserRepository userRepository;
    private final UserService userService;
    private final AuthService authService;
    private final TwoFactorService twoFactorService;
    private final PasswordResetService passwordResetService;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final MailService mailService;
    private final AuditService auditService;

    public AuthController(UserRepository userRepository,
                          UserService userService,
                          AuthService authService,
                          TwoFactorService twoFactorService,
                          PasswordResetService passwordResetService,
                          PasswordResetTokenRepository passwordResetTokenRepository,
                          MailService mailService,
                          AuditService auditService) {
        this.userRepository = userRepository;
        this.userService = userService;
        this.authService = authService;
        this.twoFactorService = twoFactorService;
        this.passwordResetService = passwordResetService;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.mailService = mailService;
        this.auditService = auditService;
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
                               @RequestParam(value = "acceptTerms", defaultValue = "false") boolean acceptTerms,
                               HttpServletRequest request,
                               Model model) {
        if (password == null || password.length() < 8) {
            model.addAttribute("error", "A senha deve conter no mínimo 8 caracteres.");
            return "auth/register";
        }
        if (!acceptTerms) {
            model.addAttribute("error", "É necessário aceitar os termos de uso e a política de privacidade.");
            return "auth/register";
        }
        if (userRepository.findByEmail(email).isPresent()) {
            model.addAttribute("error", "Este e-mail já está cadastrado no sistema.");
            return "auth/register";
        }

        try {
            RegisterRequest registerRequest = new RegisterRequest();
            registerRequest.setEmail(email);
            registerRequest.setPassword(password);
            registerRequest.setAcceptTerms(true);

            UserService.RegistrationResult result = userService.registerUser(
                    registerRequest,
                    name,
                    request.getRemoteAddr(),
                    request.getHeader("User-Agent")
            );

            // Sempre o plaintext capturado no cadastro — nunca o valor cifrado do banco
            String totpPlain = result.totpSecretPlaintext();
            String qr = twoFactorService.generateQrCodeDataUrl(totpPlain, result.user().getEmail());
            model.addAttribute("qrCode", qr);
            model.addAttribute("totpSecret", totpPlain);
            model.addAttribute("email", result.user().getEmail());
            return "auth/setup-2fa";
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage());
            return "auth/register";
        }
    }

    @GetMapping("/forgot-password")
    public String forgotPasswordPage() {
        return "auth/forgot-password";
    }

    @PostMapping("/forgot-password")
    public String processForgotPassword(@RequestParam("email") String email,
                                        HttpServletRequest request) {
        String clientIp = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        String token = passwordResetService.createResetToken(email, clientIp, userAgent);
        if (token != null) {
            mailService.sendPasswordResetEmail(email, token);
        }

        auditService.logEvent(null, "PASSWORD_RESET_REQUEST", clientIp, userAgent);
        return "redirect:/forgot-password?sent=true";
    }

    @GetMapping("/reset-password")
    public String resetPasswordPage(@RequestParam("token") String token, Model model) {
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
                                       HttpServletRequest request,
                                       Model model) {
        String clientIp = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        if (newPassword == null || newPassword.length() < 8) {
            model.addAttribute("error", "A senha deve conter no mínimo 8 caracteres.");
            model.addAttribute("token", token);
            return "auth/reset-password";
        }

        try {
            passwordResetService.resetPassword(token, newPassword, clientIp, userAgent);
            auditService.logEvent(null, "PASSWORD_RESET_SUCCESS", clientIp, userAgent);
            return "redirect:/login?resetSuccess=true";
        } catch (Exception e) {
            auditService.logEvent(null, "PASSWORD_RESET_FAILURE", clientIp, userAgent);
            model.addAttribute("error", e.getMessage());
            model.addAttribute("token", token);
            return "auth/reset-password";
        }
    }

    /**
     * Etapa 2FA via TOTP (authenticator).
     */
    @GetMapping("/login-2fa")
    public String twoFactorPage(Authentication authentication, Model model) {
        if (authentication == null) {
            return "redirect:/login";
        }
        model.addAttribute("email", authentication.getName());
        return "auth/two-factor";
    }

    @PostMapping("/login-2fa")
    public String verifyTwoFactor(@RequestParam("code") String inputCode,
                                  Authentication authentication,
                                  HttpSession session,
                                  HttpServletRequest request,
                                  Model model) {
        if (authentication == null) {
            return "redirect:/login";
        }

        String email = authentication.getName();
        String ip = request.getRemoteAddr();
        String ua = request.getHeader("User-Agent");

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            return "redirect:/login?error=true";
        }

        if (!user.isAccountNonLocked()) {
            model.addAttribute("error", "Conta temporariamente bloqueada. Tente novamente mais tarde.");
            return "auth/two-factor";
        }

        boolean valid = !user.isTwoFactorEnabled()
                || authService.verify2FACode(user, inputCode);

        if (!valid) {
            authService.registerFailed2FAAttempt(email, ip, ua);
            model.addAttribute("error", "Código TOTP inválido ou expirado. Use o aplicativo autenticador.");
            model.addAttribute("email", email);
            return "auth/two-factor";
        }

        authService.registerSuccessful2FA(email, ip, ua);
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
