package com.example.demo.controller;

import com.example.demo.model.User;
import com.example.demo.model.UserConsent;
import com.example.demo.service.LgpdService;
import com.example.demo.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;
import java.util.Map;

/**
 * Endpoints de direitos do titular (LGPD) — req. 4.6 a 4.11.
 */
@Controller
@RequestMapping("/privacy")
public class LgpdController {

    private final LgpdService lgpdService;
    private final UserService userService;

    public LgpdController(LgpdService lgpdService, UserService userService) {
        this.lgpdService = lgpdService;
        this.userService = userService;
    }

    @GetMapping
    public String privacyHome(Authentication authentication, Model model) {
        User user = currentUser(authentication);
        model.addAttribute("user", user);
        model.addAttribute("consents", lgpdService.getUserConsents(user.getId()));
        return "privacy/home";
    }

    @GetMapping("/my-data")
    public String myData(Authentication authentication, Model model) {
        User user = currentUser(authentication);
        model.addAttribute("data", lgpdService.getPersonalData(user.getId()));
        return "privacy/my-data";
    }

    @GetMapping("/export")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> export(Authentication authentication) {
        User user = currentUser(authentication);
        Map<String, Object> export = lgpdService.exportPersonalData(user.getId());
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"meus-dados.json\"")
                .contentType(MediaType.APPLICATION_JSON)
                .body(export);
    }

    @GetMapping("/consents")
    public String consents(Authentication authentication, Model model) {
        User user = currentUser(authentication);
        List<UserConsent> consents = lgpdService.getUserConsents(user.getId());
        model.addAttribute("consents", consents);
        return "privacy/consents";
    }

    @PostMapping("/consent/revoke")
    public String revokeConsent(Authentication authentication,
                                @RequestParam(defaultValue = UserService.PURPOSE_ACCOUNT) String purpose,
                                HttpServletRequest request) {
        User user = currentUser(authentication);
        lgpdService.revokeConsent(
                user.getId(),
                purpose,
                UserService.TERMS_VERSION,
                request.getRemoteAddr(),
                request.getHeader("User-Agent")
        );
        return "redirect:/privacy/consents?revoked=true";
    }

    @PostMapping("/delete")
    public String deleteData(Authentication authentication, HttpServletRequest request) {
        User user = currentUser(authentication);
        lgpdService.deletePersonalData(
                user.getId(),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")
        );
        return "redirect:/logout";
    }

    private User currentUser(Authentication authentication) {
        return userService.findByEmail(authentication.getName());
    }
}
