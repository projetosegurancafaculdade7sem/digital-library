package com.example.demo.repository;

import com.example.demo.model.SecurityAuditLog;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SecurityAuditLogRepository extends JpaRepository<SecurityAuditLog, UUID> {

    // Derived query mantem o "TOP 1" (evita NonUniqueResultException) e o lock pessimista.
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<SecurityAuditLog> findTopByOrderBySequenceNoDesc();

    List<SecurityAuditLog> findAllByOrderBySequenceNoAsc();

    /** Legado: ordenado por timestamp (usado apenas em consultas de compatibilidade). */
    Optional<SecurityAuditLog> findTopByOrderByTimestampDesc();

    List<SecurityAuditLog> findAllByOrderByTimestampAsc();

    List<SecurityAuditLog> findByUserIdOrderByTimestampDesc(UUID userId);

    List<SecurityAuditLog> findByEventTypeOrderByTimestampDesc(String eventType);
}
