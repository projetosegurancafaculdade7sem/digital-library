package com.example.demo.repository;


import com.example.demo.model.User;
import com.example.demo.security.EmailNormalizer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    boolean existsByEmailIgnoreCase(String email);

    /**
     * Registra a janela TOTP usada somente se ela for mais nova que a última aceita.
     * Atômico: duas requisições simultâneas com o mesmo código não passam as duas.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update User u set u.totpLastUsedStep = :step where u.id = :id "
            + "and (u.totpLastUsedStep is null or u.totpLastUsedStep < :step)")
    int markTotpStepUsed(@Param("id") UUID id, @Param("step") long step);

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
