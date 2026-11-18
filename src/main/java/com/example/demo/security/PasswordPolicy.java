package com.example.demo.security;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Política de nova senha aplicada no cadastro e na redefinição (item 2 do parecer).
 * A validação é compartilhada para evitar divergência entre os dois fluxos.
 */
@Component
public class PasswordPolicy {

    public static final int MIN_LENGTH = 12;
    public static final int MAX_LENGTH = 128;

    private static final Set<String> COMMON_PASSWORDS = Set.of(
            "senha123", "senha12345", "password123", "123456789abc", "qwerty123456",
            "admin123456", "digital-library", "digitallibrary123"
    );

    /** @return lista de violações; vazia quando a senha é aceita. */
    public List<String> violations(String password) {
        List<String> errors = new ArrayList<>();
        if (password == null || password.isBlank()) {
            errors.add("Informe uma senha.");
            return errors;
        }
        if (password.length() < MIN_LENGTH) {
            errors.add("Mínimo de " + MIN_LENGTH + " caracteres.");
        }
        if (password.length() > MAX_LENGTH) {
            errors.add("Máximo de " + MAX_LENGTH + " caracteres.");
        }
        if (!password.chars().anyMatch(Character::isLowerCase)) {
            errors.add("Inclua ao menos uma letra minúscula.");
        }
        if (!password.chars().anyMatch(Character::isUpperCase)) {
            errors.add("Inclua ao menos uma letra maiúscula.");
        }
        if (!password.chars().anyMatch(Character::isDigit)) {
            errors.add("Inclua ao menos um dígito.");
        }
        if (!password.chars().anyMatch(c -> !Character.isLetterOrDigit(c))) {
            errors.add("Inclua ao menos um caractere especial.");
        }
        if (COMMON_PASSWORDS.contains(password.toLowerCase(Locale.ROOT))) {
            errors.add("Escolha uma senha menos comum.");
        }
        return errors;
    }

    public boolean isValid(String password) {
        return violations(password).isEmpty();
    }

    public String message(String password) {
        return String.join(" ", violations(password));
    }

    /** Impede a reutilização da senha atual no fluxo de recuperação. */
    public void validateNewPassword(String newPassword, String currentHash,
                                    org.springframework.security.crypto.password.PasswordEncoder encoder) {
        List<String> errors = violations(newPassword);
        if (currentHash != null && encoder.matches(newPassword, currentHash)) {
            errors.add("A nova senha deve ser diferente da atual.");
        }
        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(String.join(" ", errors));
        }
    }
}
