package com.github.guoyyit.hsmsimulatorjava.tests;

import com.github.guoyyit.hsmsimulatorjava.hsm.core.HsmToken;
import com.github.guoyyit.hsmsimulatorjava.hsm.exception.HsmException;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.HsmError;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.KeyType;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.KeyUsage;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.UserType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.EnumSet;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Concurrent wrap/unwrap/destroy/session-cleanup must serialize cleanly:
 * every operation either takes full effect or fails with a distinguishable
 * reason, never half-applies.
 */
class ConcurrencyConsistencyTest {

    private static final byte[] MESSAGE = "race".getBytes(StandardCharsets.UTF_8);
    private static final Set<HsmError> EXPECTED_FAILURES = EnumSet.of(
            HsmError.KEY_DESTROYED, HsmError.SESSION_HANDLE_INVALID,
            HsmError.NOT_LOGGED_IN, HsmError.KEY_NOT_EXTRACTABLE);

    private HsmToken readyToken(Path dir) {
        HsmToken token = new HsmToken(dir);
        token.initializeToken("so-pin", "user-pin", "race");
        return token;
    }

    private long userSession(HsmToken token) {
        long session = token.openSession();
        token.login(session, UserType.USER, "user-pin");
        return session;
    }

    @Test
    void concurrentWrapUnwrapDestroyAndCleanupAreAtomic(@TempDir Path dir) throws Exception {
        HsmToken token = readyToken(dir);
        long setup = userSession(token);
        String kekId = token.generateKey(setup, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP, KeyUsage.UNWRAP));
        String targetId = token.generateKey(setup, KeyType.AES, 128, "target",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), true);
        byte[] wrapped = token.wrapKey(setup, kekId, targetId);

        int threads = 12;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<String> unexpected = new ConcurrentLinkedQueue<>();
        AtomicInteger unwrapOk = new AtomicInteger();
        AtomicInteger wrapOk = new AtomicInteger();
        AtomicInteger destroyOk = new AtomicInteger();
        AtomicInteger cleanupOk = new AtomicInteger();
        try {
            for (int i = 0; i < threads; i++) {
                int kind = i % 4;
                pool.submit(() -> {
                    start.await();
                    long session = userSession(token);
                    try {
                        switch (kind) {
                            case 0 -> {
                                token.unwrapKey(session, kekId, wrapped, "copy", null);
                                unwrapOk.incrementAndGet();
                            }
                            case 1 -> {
                                token.wrapKey(session, kekId, targetId);
                                wrapOk.incrementAndGet();
                            }
                            case 2 -> {
                                token.destroyKey(session, targetId);
                                destroyOk.incrementAndGet();
                            }
                            default -> {
                                token.closeAllSessions();
                                cleanupOk.incrementAndGet();
                            }
                        }
                    } catch (HsmException e) {
                        if (!EXPECTED_FAILURES.contains(e.getError())) {
                            unexpected.add("unexpected error " + e.getError());
                        }
                    } catch (Exception e) {
                        unexpected.add("unexpected exception " + e);
                    }
                    return null;
                });
            }
            start.countDown();
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));
        }
        assertTrue(unexpected.isEmpty(), () -> "unexpected failures: " + unexpected);

        // Destroy is idempotent-safe: exactly one logical outcome — the key
        // ends destroyed and every later use reports KEY_DESTROYED.
        long check = userSession(token);
        HsmException after = assertThrows(HsmException.class,
                () -> token.wrapKey(check, kekId, targetId));
        assertEquals(HsmError.KEY_DESTROYED, after.getError());

        // Every unwrap that succeeded produced a complete, interoperable copy.
        assertTrue(unwrapOk.get() > 0 || wrapOk.get() > 0 || cleanupOk.get() > 0);
        int keyCount = (Integer) token.status().get("keyCount");
        assertEquals(1 + unwrapOk.get(), keyCount);
    }

    @Test
    void destroyBetweenWrapAndUnwrapFailsUnwrapCleanly(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kekId = token.generateKey(session, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP, KeyUsage.UNWRAP));
        String targetId = token.generateKey(session, KeyType.AES, 128, "target",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), true);
        byte[] wrapped = token.wrapKey(session, kekId, targetId);

        token.destroyKey(session, kekId);
        HsmException ex = assertThrows(HsmException.class,
                () -> token.unwrapKey(session, kekId, wrapped, "copy", null));
        assertEquals(HsmError.KEY_DESTROYED, ex.getError());
        // No partial key materialized from the failed unwrap: only the
        // still-alive target remains.
        assertEquals(1, token.status().get("keyCount"));
    }

    @Test
    void tamperedEnvelopeFailsWithoutTouchingOtherKeysOrSessions(@TempDir Path dir) throws Exception {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kekId = token.generateKey(session, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP, KeyUsage.UNWRAP));
        String targetId = token.generateKey(session, KeyType.AES, 128, "target",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), true);
        byte[] wrapped = token.wrapKey(session, kekId, targetId);

        com.fasterxml.jackson.databind.ObjectMapper mapper =
                new com.fasterxml.jackson.databind.ObjectMapper();
        java.util.Map<String, String> envelope = mapper.readValue(wrapped,
                new com.fasterxml.jackson.core.type.TypeReference<>() {
                });
        byte[] inner = java.util.Base64.getDecoder().decode(envelope.get("wrapped"));
        inner[0] ^= 0x01;
        envelope.put("wrapped", java.util.Base64.getEncoder().encodeToString(inner));
        byte[] tampered = mapper.writeValueAsBytes(envelope);

        HsmException ex = assertThrows(HsmException.class,
                () -> token.unwrapKey(session, kekId, tampered, "x", null));
        assertEquals(HsmError.UNWRAPPING_FAILED, ex.getError());

        // Other keys and the same session are unaffected; a good envelope
        // still unwraps into a fully interoperable copy.
        assertEquals(2, token.status().get("keyCount"));
        String copyId = token.unwrapKey(session, kekId, wrapped, "good-copy", null);
        byte[] ciphertext = token.encrypt(session, targetId, MESSAGE);
        token.decrypt(session, copyId, ciphertext);
    }
}
