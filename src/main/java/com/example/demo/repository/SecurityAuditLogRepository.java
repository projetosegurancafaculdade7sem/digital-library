package com.example.demo.repository;

import com.example.demo.model.SecurityAuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SecurityAuditLogRepository extends JpaRepository<SecurityAuditLog, UUID> {

    Optional<SecurityAuditLog> findTopByOrderByTimestampDesc();

    List<SecurityAuditLog> findByUserIdOrderByTimestampDesc(UUID userID);

    List<SecurityAuditLog> findByEventTypeOrderByTimestampDesc(String eventType);

}
