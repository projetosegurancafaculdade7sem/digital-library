package com.example.demo.repository;


import com.example.demo.model.User;
import com.example.demo.security.EmailNormalizer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    boolean existsByEmailIgnoreCase(String email);

    /**
     * Busca pelo e-mail digitado pelo usuário: primeiro na forma canônica e, para contas
     * antigas gravadas antes da normalização, pelo valor exato informado.
     */
    default Optional<User> findByLoginEmail(String rawEmail) {
        if (rawEmail == null || rawEmail.isBlank()) {
            return Optional.empty();
        }
        Optional<User> user = findByEmail(EmailNormalizer.normalize(rawEmail));
        return user.isPresent() ? user : findByEmail(rawEmail.trim());
    }
}
