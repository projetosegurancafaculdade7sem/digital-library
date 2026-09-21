package com.example.demo.controller;

import com.example.demo.service.AuditService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;

/**
 * Análise de logs de auditoria (req. 5.4).
 */
@Controller
@RequestMapping("/admin/audit")
public class AuditController {

    private final AuditService auditService;

    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping("/analyze")
    public String analyzePage(Model model) {
        model.addAttribute("analysis", auditService.analyzeLogs());
        return "admin/audit-analysis";
    }

    @GetMapping("/analyze.json")
    @ResponseBody
    public Map<String, Object> analyzeJson() {
        return auditService.analyzeLogs();
    }
}
