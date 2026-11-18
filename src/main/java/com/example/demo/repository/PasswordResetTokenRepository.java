package com.example.demo.repository;

import com.example.demo.model.PasswordResetToken;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, UUID> {

    Optional<PasswordResetToken> findByTokenHash(String tokenHash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select t from PasswordResetToken t where t.tokenHash = :hash")
    Optional<PasswordResetToken> findByTokenHashForUpdate(@Param("hash") String hash);

    List<PasswordResetToken> findByUserId(UUID userId);

    List<PasswordResetToken> findByUserIdAndUsedFalseAndRevokedAtIsNull(UUID userId);

    /** Consumo atômico: somente uma transação consegue marcar o token como usado. */
    @Modifying
    @Query("update PasswordResetToken t set t.used = true, t.usedAt = :now "
            + "where t.id = :id and t.used = false and t.revokedAt is null")
    int consumeIfUnused(@Param("id") UUID id, @Param("now") Instant now);

    /** Uma nova solicitação invalida todos os tokens anteriores do mesmo usuário. */
    @Modifying
    @Query("update PasswordResetToken t set t.revokedAt = :now "
            + "where t.userId = :userId and t.used = false and t.revokedAt is null")
    void revokeAllActiveForUser(@Param("userId") UUID userId, @Param("now") Instant now);

    void deleteByUserId(UUID userId);
}
