package com.example.demo.controller;


import com.example.demo.dto.request.LoginForm;
import com.example.demo.dto.request.RegisterRequest;
import com.example.demo.dto.request.ResetPasswordForm;
import com.example.demo.model.User;
import com.example.demo.service.AuthService;
import com.example.demo.service.PasswordResetService;
import com.example.demo.service.TwoFactorService;
import com.example.demo.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.Response;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.UUID;

@Controller
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final PasswordResetService passwordResetService;
    private final UserService userService;
    private final TwoFactorService twoFactorService;

    // route to register
    @GetMapping("/register")
    public String registerPage(Model model) {
        if (!model.containsAttribute("registerForm")) {
            model.addAttribute("registerForm", new RegisterRequest());
        }
        return "register";
    }

    // Processes the registration form
    @PostMapping("/register")
    public String handleRegister(@Valid @ModelAttribute("registerForm") RegisterRequest form,
                                 BindingResult bindingResult,
                                 RedirectAttributes redirectAttributes) {

        if (bindingResult.hasErrors()) {
            redirectAttributes.addFlashAttribute("org.springframework.validation.BindingResult.registerForm", bindingResult);
            redirectAttributes.addFlashAttribute("registerForm", form);
            return "redirect:/register";
        }

        try {
            userService.registerUser(form);
            redirectAttributes.addFlashAttribute("successMessage", "Account created successfully! Please log in.");
            return "redirect:/login";
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
            redirectAttributes.addFlashAttribute("registerForm", form);
            return "redirect:/register";
        }
    }

    //loads login screen
    @GetMapping("/login")
    public String loginPage(Model model,
                            @RequestParam(value = "error", required = false) String error,
                            @RequestParam(value = "logout", required = false) String logout) {
        if (!model.containsAttribute("loginForm")) {
            model.addAttribute("loginForm", new LoginForm());
        }
        if (error != null) {
            model.addAttribute("successMessage", "You've ended your session safely");
        }
        return "login";
    }

    // POST /login-custom (Ajustado para o fluxo em duas etapas)
    @PostMapping("/login-custom")
    public String handleLogin(@ModelAttribute("loginForm") LoginForm form,
                              HttpServletRequest request,
                              HttpSession session,
                              RedirectAttributes redirectAttributes) {
        try {
            // Passo 1: Autenticação primária (Email + Senha)
            User user = authService.authenticatePrimary(form.getEmail(), form.getPassword());

            // Se 2FA estiver ativado, valida o token digitado ou redireciona para a tela de 2FA
            if (user.is_2fa_enabled()) {
                if (form.getTotpcode() == null || form.getTotpcode().isBlank()) {
                    session.setAttribute("PRE_AUTH_USER_ID", user.getId());
                    return "redirect:/login-2fa";
                }

                boolean is2faValid = authService.verify2FACode(user, form.getTotpcode());
                if (!is2faValid) {
                    redirectAttributes.addFlashAttribute("errorMessage", "Código 2FA inválido ou expirado.");
                    return "redirect:/login";
                }
            }

            // Sessão autorizada
            session.setAttribute("LOGGED_USER_ID", user.getId());
            return "redirect:/dashboard";

        } catch (IllegalArgumentException | IllegalStateException e) {
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
            return "redirect:/login";
        }
    }

    // GET /setup-2fa: Renderiza a tela de ativação do 2FA exibindo o QR Code
    @GetMapping("/setup-2fa")
    public String setup2FAPage(HttpSession session, Model model) {
        UUID userId = (UUID) session.getAttribute("LOGGED_USER_ID");
        if (userId == null) {
            return "redirect:/login";
        }

        User user = userService.findById(userId);
        String secret = userService.setup2FA(userId);
        String qrCodeDataUrl = twoFactorService.generateQrCodeDataUrl(secret, user.getEmail());

        model.addAttribute("qrCodeUrl", qrCodeDataUrl);
        model.addAttribute("secret", secret);
        return "setup-2fa";
    }

    // POST /enable-2fa: Confirma o primeiro código e ativa o 2FA definitivamente
    @PostMapping("/enable-2fa")
    public String enable2FA(@RequestParam("code") String code,
                            HttpSession session,
                            RedirectAttributes redirectAttributes) {
        UUID userId = (UUID) session.getAttribute("LOGGED_USER_ID");
        try {
            userService.enable2FA(userId, code);
            redirectAttributes.addFlashAttribute("successMessage", "2FA ativado com sucesso!");
            return "redirect:/dashboard";
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
            return "redirect:/setup-2fa";
        }
    }

    //Renders the password recovery page.
    @GetMapping("/forgot-password")
    public String forgotPasswordPage(){
        return "forgot-password";
    }

    //process to recover email
    @PostMapping("/forgot-password")
    public String handleForgotPassword(@RequestParam("email") String email,
                                     HttpServletRequest request,
                                     RedirectAttributes redirectAttributes){

        String clientIp = getClientIP(request);
        String userAgent = request.getHeader("User-Agent");

        //creates a resetToken that allows the user to reset it.
        passwordResetService.createResetToken(email, clientIp, userAgent);

        redirectAttributes.addFlashAttribute("successMessage",
                "If is your e-mail registered, you'll receive the instructions to recover your password :-)");


        return "redirect:/forgot-password";
    }

    @GetMapping("/reset-password")
    public String resetPasswordPage(@RequestParam("token") String token, Model model){
        ResetPasswordForm form = new ResetPasswordForm();
        form.setToken(token);
        model.addAttribute("resetPasswordForm", form);
        return "reset-password";
    }

    @PostMapping("/reset-password")
    public String handleResetPassword(@ModelAttribute("resetPasswordForm") ResetPasswordForm form, HttpServletRequest request, RedirectAttributes redirectAttributes){

        if(!form.getNewPassword().equals(form.getConfirmPassword())){
            redirectAttributes.addFlashAttribute("errorMessage", "Both password do not match");
            return "redirect:/reset-password?token=" + form.getToken();
        }
        try{
            String clientIp = getClientIP(request);
            String userAgent = request.getHeader("User-Agent");

            passwordResetService.resetPassword(form.getToken(), form.getNewPassword(), clientIp, userAgent);
            redirectAttributes.addFlashAttribute("successMessage", "Password successfully changed");
            return "redirect:/login";
        } catch(IllegalArgumentException | IllegalStateException error){
            redirectAttributes.addFlashAttribute("errorMessage", error.getMessage());
            return "redirect:/login";
        }
    }



    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty()) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }

    // Renders the Step 2 screen (for entering the 2FA code only)
    @GetMapping("/login-2fa")
    public String login2faPage(HttpSession session, Model model) {
        UUID preAuthUserId = (UUID) session.getAttribute("PRE_AUTH_USER_ID");
        if (preAuthUserId == null) {
            return "redirect:/login";
        }
        return "login-2fa"; // Thymeleaf template name (login-2fa.html)
    }

    //Processes the exclusive validation for Login Step 2.
    @PostMapping("/login-2fa")
    public String handleLogin2fa(@RequestParam("totpcode") String totpcode,
                                 HttpSession session,
                                 RedirectAttributes redirectAttributes) {
        UUID preAuthUserId = (UUID) session.getAttribute("PRE_AUTH_USER_ID");
        if (preAuthUserId == null) {
            return "redirect:/login";
        }

        try {
            User user = userService.findById(preAuthUserId);
            boolean is2faValid = authService.verify2FACode(user, totpcode);

            if (!is2faValid) {
                redirectAttributes.addFlashAttribute("errorMessage", "Código 2FA inválido ou expirado.");
                return "redirect:/login-2fa";
            }

            // Success! Promotes the session for a fully authenticated user.
            session.removeAttribute("PRE_AUTH_USER_ID");
            session.setAttribute("LOGGED_USER_ID", user.getId());
            return "redirect:/dashboard";

        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Erro na validação do 2FA.");
            return "redirect:/login";
        }
    }

}
