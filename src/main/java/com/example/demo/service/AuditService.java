package com.example.demo.service;


import com.example.demo.model.SecurityAuditLog;
import com.example.demo.repository.SecurityAuditLogRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuditService {


    private final SecurityAuditLogRepository auditLogRepository;
    private static final String GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    @Transactional
    public void logEvent(UUID userId, String eventType, String ipAddress, String userAgent){
        Instant now = Instant.now();

        //gets the last log to take the logHash and make de chain
        String previousHash = auditLogRepository.findTopByOrderByTimestampDesc()
                .map(SecurityAuditLog::getLogHash)
                .orElse(GENESIS_HASH);

        String currentHash = calculateHash(userId, eventType, ipAddress, userAgent, now, previousHash);

        SecurityAuditLog log = SecurityAuditLog.builder()
                .userId(userId)
                .eventType(eventType)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .timestamp(now)
                .previousHash(previousHash)
                .logHash(currentHash)
                .build();

        auditLogRepository.save(log);
    }

    private String calculateHash(UUID userId, String eventType, String ipAddress, String userAgent, Instant timestamp, String previousHash){

        try {
            String rawData = String.format("%s|%s|%s|%s|%s|%s",
                    userId != null ? userId.toString() : "ANONYMOUS",
                    eventType,
                    ipAddress,
                    userAgent != null ? userAgent : "",
                    timestamp.toString(),
                    previousHash);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(rawData.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();

            for (byte b : hashBytes){

                String hex = Integer.toHexString(0xff & b);
                if(hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e){
            throw new RuntimeException("error calculating audit hash",e);
        }
    }
}
