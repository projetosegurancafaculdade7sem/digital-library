package com.example.demo.service;

import com.example.demo.repository.SecurityAuditLogRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/** Cadeia HMAC, sequência, tampering e concorrência (item 5 do parecer). */
@SpringBootTest
@ActiveProfiles("test")
class AuditIntegrityTest {

    @Autowired private AuditService auditService;
    @Autowired private SecurityAuditLogRepository repository;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private PlatformTransactionManager transactionManager;
    @PersistenceContext private EntityManager entityManager;

    @BeforeEach
    void clean() {
        repository.deleteAllInBatch(); // bulk: não dispara @PreRemove
    }

    @Test
    void cadeiaValidaSequencialETamperingEGenericamenteDetectado() {
        UUID user = UUID.randomUUID();
        auditService.logEvent(user, "LOGIN_SUCCESS", "127.0.0.1", "JUnit");
        auditService.logEvent(user, "LOGIN_FAILED_BAD_CREDENTIALS", "127.0.0.1", "JUnit");
        auditService.logEvent(user, "LOGIN_SUCCESS_2FA", "127.0.0.1", "JUnit");

        assertTrue(auditService.verifyIntegrityChain());
        assertEquals(3, repository.count());
        assertEquals(1L, repository.findAllByOrderBySequenceNoAsc().get(0).getSequenceNo());

        TransactionTemplate tx = new TransactionTemplate(transactionManager);
        tx.executeWithoutResult(status -> {
            jdbcTemplate.update("update security_audit_logs set event_type = ? where sequence_no = ?",
                    "TAMPERED", 1L);
            entityManager.clear();
        });

        assertFalse(auditService.verifyIntegrityChain(), "Alteração privilegiada deve quebrar a cadeia");
    }

    @Test
    void escritaConcorrenteMantemSequenciaUnicaECadeiaValida() throws Exception {
        int threads = 5;
        int eventsPerThread = 4;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);

        try {
            for (int t = 0; t < threads; t++) {
                final int index = t;
                pool.submit(() -> {
                    start.await();
                    for (int i = 0; i < eventsPerThread; i++) {
                        auditService.logEvent(UUID.randomUUID(), "CONCURRENT_EVENT_" + index,
                                "127.0.0.1", "JUnit");
                    }
                    return null;
                });
            }
            start.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }

        assertEquals(threads * eventsPerThread, repository.count());
        assertTrue(auditService.verifyIntegrityChain());
        long distinctSequences = repository.findAllByOrderBySequenceNoAsc().stream()
                .map(log -> log.getSequenceNo())
                .distinct()
                .count();
        assertEquals(threads * eventsPerThread, distinctSequences);
    }
}
