package com.example.demo.service;

import com.example.demo.model.SecurityAuditLog;
import com.example.demo.repository.SecurityAuditLogRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

/**
 * Cadeia de integridade HMAC-SHA256 (item 5 do parecer).
 *
 * <p>Um SHA-256 simples pode ser recalculado por quem tem acesso de escrita ao banco.
 * Aqui o HMAC usa uma chave separada, fornecida por variável de ambiente/cofre, e um número
 * de sequência monotônico. A gravação é serializada por um lock justo e executada dentro de
 * sua própria transação, evitando gaps e previousHash duplicados sob concorrência.</p>
 */
@Service
public class AuditService {

    public static final String GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final SecurityAuditLogRepository auditLogRepository;
    private final TransactionTemplate transactionTemplate;
    private final byte[] hmacKey;
    /** Serializa a atribuição de sequência em instância única (ver docs/SEGURANCA.md). */
    private final ReentrantLock writeLock = new ReentrantLock(true);

    public AuditService(SecurityAuditLogRepository auditLogRepository,
                        PlatformTransactionManager transactionManager,
                        @Value("${security.audit.hmac-key-base64}") String hmacKeyBase64) {
        this.auditLogRepository = auditLogRepository;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        this.hmacKey = Base64.getDecoder().decode(hmacKeyBase64);
        if (this.hmacKey.length < 32) {
            throw new IllegalStateException("security.audit.hmac-key-base64 deve ter ao menos 32 bytes.");
        }
    }

    public void logEvent(UUID userId, String eventType, String ipAddress, String userAgent) {
        writeLock.lock();
        try {
            // timestamp(6) no banco: truncar antes de calcular o HMAC evita divergencia
            // entre o valor em memoria e o valor efetivamente persistido.
            Instant timestamp = Instant.now().truncatedTo(ChronoUnit.MICROS);
            transactionTemplate.executeWithoutResult(status -> persistEvent(
                    userId, eventType, ipAddress, userAgent, timestamp));
        } finally {
            writeLock.unlock();
        }
    }

    private void persistEvent(UUID userId, String eventType, String ipAddress,
                              String userAgent, Instant timestamp) {
        SecurityAuditLog previous = auditLogRepository.findTopByOrderBySequenceNoDesc().orElse(null);
        long sequence = previous == null ? 1L : previous.getSequenceNo() + 1;
        String previousHash = previous == null ? GENESIS_HASH : previous.getLogHash();
        String hash = calculateHmac(userId, eventType, ipAddress, userAgent,
                timestamp, previousHash, sequence);

        SecurityAuditLog log = SecurityAuditLog.builder()
                .sequenceNo(sequence)
                .userId(userId)
                .eventType(eventType)
                .ipAddress(ipAddress != null ? ipAddress : "unknown")
                .userAgent(userAgent)
                .timestamp(timestamp)
                .previousHash(previousHash)
                .hmacHash(hash)
                .logHash(hash) // compatibilidade com o campo historicamente exibido no painel
                .build();

        auditLogRepository.saveAndFlush(log);
    }

    /** Verifica sequência, ponteiro anterior e HMAC de cada registro. */
    public boolean verifyIntegrityChain() {
        List<SecurityAuditLog> logs = auditLogRepository.findAllByOrderBySequenceNoAsc();
        String expectedPrevious = GENESIS_HASH;
        long expectedSequence = 1L;
        for (SecurityAuditLog log : logs) {
            if (log.getSequenceNo() == null || log.getSequenceNo() != expectedSequence
                    || log.getPreviousHash() == null
                    || !constantEquals(expectedPrevious, log.getPreviousHash())) {
                return false;
            }
            String recalculated = calculateHmac(
                    log.getUserId(), log.getEventType(), log.getIpAddress(), log.getUserAgent(),
                    log.getTimestamp(), log.getPreviousHash(), log.getSequenceNo());
            if (!constantEquals(recalculated, log.getHmacHash())
                    || !constantEquals(recalculated, log.getLogHash())) {
                return false;
            }
            expectedPrevious = log.getHmacHash();
            expectedSequence++;
        }
        return true;
    }

    /** Análise para evidência no painel administrativo (req. 5.4). */
    public Map<String, Object> analyzeLogs() {
        List<SecurityAuditLog> logs = auditLogRepository.findAllByOrderBySequenceNoAsc();

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
            recent.add(String.format("%s | seq=%s | %s | user=%s | ip=%s | hmac=%s...",
                    l.getTimestamp(), l.getSequenceNo(), l.getEventType(), l.getUserId(),
                    l.getIpAddress(), l.getHmacHash() != null && l.getHmacHash().length() > 12
                            ? l.getHmacHash().substring(0, 12) : l.getHmacHash()));
        }

        Map<String, Object> analysis = new LinkedHashMap<>();
        analysis.put("totalEvents", logs.size());
        analysis.put("successEvents", successes);
        analysis.put("failureOrLockEvents", failures);
        analysis.put("eventsByType", byEvent);
        analysis.put("integrityChainValid", verifyIntegrityChain());
        analysis.put("hashAlgorithm", HMAC_ALGORITHM);
        analysis.put("lastSequence", logs.isEmpty() ? 0L : logs.get(logs.size() - 1).getSequenceNo());
        analysis.put("recentEventsSample", recent);
        analysis.put("analysisNote",
                "Cadeia HMAC-SHA256 com sequência monotônica e chave fora do banco. "
                        + "Picos em LOGIN_FAILED_* ou ACCOUNT_LOCKED_* indicam possível força bruta.");
        return analysis;
    }

    private String calculateHmac(UUID userId, String eventType, String ipAddress,
                                 String userAgent, Instant timestamp,
                                 String previousHash, long sequence) {
        try {
            String rawData = String.format("%d|%s|%s|%s|%s|%s|%s",
                    sequence,
                    userId != null ? userId.toString() : "ANONYMOUS",
                    eventType,
                    ipAddress,
                    userAgent != null ? userAgent : "",
                    timestamp.toString(),
                    previousHash);

            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(hmacKey, HMAC_ALGORITHM));
            byte[] digest = mac.doFinal(rawData.getBytes(StandardCharsets.UTF_8));
            return hex(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Erro ao calcular HMAC de auditoria", e);
        }
    }

    private boolean constantEquals(String expected, String actual) {
        if (expected == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    private String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
