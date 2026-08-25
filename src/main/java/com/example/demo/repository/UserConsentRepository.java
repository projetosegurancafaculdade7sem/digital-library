package com.example.demo.repository;

import com.example.demo.model.UserConsent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserConsentRepository extends JpaRepository<UserConsent, UUID> {
    List<UserConsent> findByUserIdOrderByGrantedAtDesc(UUID userId);

    Optional<UserConsent> findTopByUserIdAndPurposeOrderByGrantedAtDesc(UUID userId, String purpose);
}
