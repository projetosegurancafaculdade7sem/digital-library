package com.example.demo.security;

import java.util.Locale;

/**
 * Forma canônica do e-mail (trim + minúsculas). Evita contas duplicadas por variação de
 * maiúsculas/minúsculas e impede que "Admin@..." herde o papel de "admin@...".
 */
public final class EmailNormalizer {

    private EmailNormalizer() {
    }

    public static String normalize(String email) {
        return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
    }
}
