package com.example.demo.service;


import com.example.demo.repository.SecurityAuditLogRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuditService {


    private final SecurityAuditLogRepository auditLogRepository;
    private static final String GENESIS_HASH = "0000000000000000000000000000000000000000";

    @Transactional
    private void logEvent(UUID userId, String eventType, String ipAddress, String userAgent){
        Instant now = Instant.now();

        String previousHash = auditLogRepository.findTop
    }
}
