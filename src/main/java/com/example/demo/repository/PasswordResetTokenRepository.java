package com.example.demo.repository;

import com.example.demo.model.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, UUID> {

    Optional<PasswordResetToken> findByTokenHashAndUsedFalse(String tokenHash);

    List<PasswordResetToken> findByUserIdAndUsedFalse(UUID userId);
}
