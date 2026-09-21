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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final SecurityAuditLogRepository auditLogRepository;
    private static final String GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    @Transactional
    public void logEvent(UUID userId, String eventType, String ipAddress, String userAgent) {
        Instant now = Instant.now();

        String previousHash = auditLogRepository.findTopByOrderByTimestampDesc()
                .map(SecurityAuditLog::getLogHash)
                .orElse(GENESIS_HASH);

        String currentHash = calculateHash(userId, eventType, ipAddress, userAgent, now, previousHash);

        SecurityAuditLog log = SecurityAuditLog.builder()
                .userId(userId)
                .eventType(eventType)
                .ipAddress(ipAddress != null ? ipAddress : "unknown")
                .userAgent(userAgent)
                .timestamp(now)
                .previousHash(previousHash)
                .logHash(currentHash)
                .build();

        auditLogRepository.save(log);
    }

    /**
     * Verifica a cadeia de integridade SHA-256 (req. 5.3).
     */
    public boolean verifyIntegrityChain() {
        List<SecurityAuditLog> logs = auditLogRepository.findAllByOrderByTimestampAsc();
        String expectedPrevious = GENESIS_HASH;
        for (SecurityAuditLog log : logs) {
            if (!expectedPrevious.equals(log.getPreviousHash())) {
                return false;
            }
            String recalculated = calculateHash(
                    log.getUserId(),
                    log.getEventType(),
                    log.getIpAddress(),
                    log.getUserAgent(),
                    log.getTimestamp(),
                    log.getPreviousHash()
            );
            if (!recalculated.equals(log.getLogHash())) {
                return false;
            }
            expectedPrevious = log.getLogHash();
        }
        return true;
    }

    /**
     * Exemplo de análise de logs para evidência (req. 5.4).
     */
    public Map<String, Object> analyzeLogs() {
        List<SecurityAuditLog> logs = auditLogRepository.findAllByOrderByTimestampAsc();

        Map<String, Long> byEvent = logs.stream()
                .collect(Collectors.groupingBy(SecurityAuditLog::getEventType, Collectors.counting()));

        long failures = byEvent.entrySet().stream()
                .filter(e -> e.getKey().contains("FAIL") || e.getKey().contains("LOCKED"))
                .mapToLong(Map.Entry::getValue)
                .sum();

        long successes = byEvent.entrySet().stream()
                .filter(e -> e.getKey().contains("SUCCESS"))
                .mapToLong(Map.Entry::getValue)
                .sum();

        List<String> recent = new ArrayList<>();
        int from = Math.max(0, logs.size() - 10);
        for (int i = from; i < logs.size(); i++) {
            SecurityAuditLog l = logs.get(i);
            recent.add(String.format("%s | %s | user=%s | ip=%s | hash=%s...",
                    l.getTimestamp(),
                    l.getEventType(),
                    l.getUserId(),
                    l.getIpAddress(),
                    l.getLogHash() != null && l.getLogHash().length() > 12
                            ? l.getLogHash().substring(0, 12) : l.getLogHash()));
        }

        Map<String, Object> analysis = new LinkedHashMap<>();
        analysis.put("totalEvents", logs.size());
        analysis.put("successEvents", successes);
        analysis.put("failureOrLockEvents", failures);
        analysis.put("eventsByType", byEvent);
        analysis.put("integrityChainValid", verifyIntegrityChain());
        analysis.put("recentEventsSample", recent);
        analysis.put("analysisNote",
                "Contagem de eventos de autenticação/LGPD com verificação da cadeia hash. "
                        + "Picos em LOGIN_FAILED_* ou ACCOUNT_LOCKED_* indicam possível força bruta.");
        return analysis;
    }

    private String calculateHash(UUID userId, String eventType, String ipAddress,
                                 String userAgent, Instant timestamp, String previousHash) {
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
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("error calculating audit hash", e);
        }
    }
}
