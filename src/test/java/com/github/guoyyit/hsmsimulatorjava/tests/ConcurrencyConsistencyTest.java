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
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Concurrent wrap / unwrap / destroy / cleanup must each take full effect or
 * no effect at all, failures must carry distinguishable reasons, and a bad
 * envelope must never disturb other keys or sessions.
 */
class ConcurrencyConsistencyTest {

    private static final byte[] MESSAGE = "concurrent".getBytes(StandardCharsets.UTF_8);

    private HsmToken readyToken(Path dir) {
        HsmToken token = new HsmToken(dir);
        token.initializeToken("so-pin", "user-pin", "concurrency");
        return token;
    }

    private long userSession(HsmToken token) {
        long session = token.openSession();
        token.login(session, UserType.USER, "user-pin");
        return session;
    }

    @Test
    void concurrentWrapAndDestroyAreAtomicInEitherOrder(@TempDir Path dir) throws Exception {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kek = token.generateKey(session, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP, KeyUsage.UNWRAP));
        EnumSet<KeyUsage> usages = EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);

        int pairs = 8;
        ExecutorService pool = Executors.newFixedThreadPool(pairs * 2);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<String> outcomes = new ConcurrentLinkedQueue<>();
        try {
            for (int i = 0; i < pairs; i++) {
                String target = token.generateKey(session, KeyType.AES, 128, "t" + i, usages, true);
                pool.submit(() -> {
                    start.await();
                    try {
                        byte[] wrapped = token.wrapKey(session, kek, target);
                        // A successful wrap must be fully usable: unwrap it
                        // and prove the copy decrypts like the source did.
                        String copy = token.unwrapKey(session, kek, wrapped, "c", usages);
                        byte[] ct = token.encrypt(session, copy, MESSAGE);
                        assertArrayEquals(MESSAGE, token.decrypt(session, copy, ct));
                        outcomes.add("wrapped");
                    } catch (HsmException e) {
                        assertEquals(HsmError.KEY_DESTROYED, e.getError());
                        outcomes.add("destroyed-first");
                    }
                    return null;
                });
                pool.submit(() -> {
                    start.await();
                    token.destroyKey(session, target);
                    outcomes.add("destroyer");
                    return null;
                });
            }
            start.countDown();
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));
        }
        // Every wrap either fully succeeded (envelope unwrapped into a working
        // copy) or failed cleanly with KEY_DESTROYED. No half states.
        assertEquals(pairs * 2, outcomes.size());
        assertEquals(pairs, outcomes.stream().filter("destroyer"::equals).count());
    }

    @Test
    void concurrentCleanupLeavesNoHalfValidSessions(@TempDir Path dir) throws Exception {
        HsmToken token = readyToken(dir);
        int workers = 12;
        // All sessions exist before the race starts, so the cleanup is
        // guaranteed to invalidate every one of them.
        List<Long> handles = new java.util.ArrayList<>();
        for (int i = 0; i < workers; i++) {
            handles.add(userSession(token));
        }
        ExecutorService pool = Executors.newFixedThreadPool(workers + 1);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger succeeded = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        try {
            for (int i = 0; i < workers; i++) {
                long session = handles.get(i);
                pool.submit(() -> {
                    start.await();
                    try {
                        token.digest(session, MESSAGE);
                        succeeded.incrementAndGet();
                    } catch (HsmException e) {
                        // After cleanup the handle is simply gone.
                        assertEquals(HsmError.SESSION_HANDLE_INVALID, e.getError());
                        rejected.incrementAndGet();
                    }
                    return null;
                });
            }
            pool.submit(() -> {
                start.await();
                token.closeAllSessions();
                return null;
            });
            start.countDown();
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));
        }
        assertEquals(0, token.status().get("openSessions"));
        // Every digest either fully succeeded or failed on the invalid handle.
        assertEquals(workers, succeeded.get() + rejected.get());
        // New sessions are unaffected by the cleanup.
        long fresh = userSession(token);
        assertEquals(32, token.digest(fresh, MESSAGE).length);
    }

    @Test
    void destroyedWrappingKeyFailsUnwrapWithDistinguishableReason(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kek = token.generateKey(session, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP, KeyUsage.UNWRAP));
        EnumSet<KeyUsage> usages = EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
        String target = token.generateKey(session, KeyType.AES, 128, "t", usages, true);
        byte[] wrapped = token.wrapKey(session, kek, target);

        token.destroyKey(session, kek);
        HsmException ex = assertThrows(HsmException.class,
                () -> token.unwrapKey(session, kek, wrapped, "x", usages));
        assertEquals(HsmError.KEY_DESTROYED, ex.getError());

        token.destroyKey(session, target);
        HsmException wrapEx = assertThrows(HsmException.class,
                () -> token.wrapKey(session, kek, target));
        assertEquals(HsmError.KEY_DESTROYED, wrapEx.getError());
    }

    @Test
    void tamperedOrMismatchedEnvelopeNeverAffectsOtherKeysOrSessions(@TempDir Path dir)
            throws Exception {
        HsmToken token = readyToken(dir);
        long sessionA = userSession(token);
        long sessionB = userSession(token);
        String kek = token.generateKey(sessionA, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP, KeyUsage.UNWRAP));
        EnumSet<KeyUsage> usages = EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
        String target = token.generateKey(sessionA, KeyType.AES, 128, "t", usages, true);
        byte[] good = token.wrapKey(sessionA, kek, target);
        byte[] goodCiphertext = token.encrypt(sessionA, target, MESSAGE);

        com.fasterxml.jackson.databind.ObjectMapper mapper =
                new com.fasterxml.jackson.databind.ObjectMapper();

        // 1. Bit-flipped ciphertext is rejected.
        Map<String, String> envelope = mapper.readValue(good,
                new com.fasterxml.jackson.core.type.TypeReference<>() {
                });
        byte[] inner = java.util.Base64.getDecoder().decode(envelope.get("wrapped"));
        inner[inner.length - 1] ^= 0x01;
        envelope.put("wrapped", java.util.Base64.getEncoder().encodeToString(inner));
        byte[] tampered = mapper.writeValueAsBytes(envelope);
        HsmException tamperedEx = assertThrows(HsmException.class,
                () -> token.unwrapKey(sessionA, kek, tampered, "x", usages));
        assertEquals(HsmError.UNWRAPPING_FAILED, tamperedEx.getError());

        // 2. An envelope whose declared usages contradict the caller template
        //    is rejected on usage grounds.
        HsmException mismatch = assertThrows(HsmException.class,
                () -> token.unwrapKey(sessionA, kek, good, "x",
                        EnumSet.of(KeyUsage.SIGN)));
        assertEquals(HsmError.KEY_USAGE_VIOLATION, mismatch.getError());

        // 3. Garbage bytes are rejected as malformed.
        HsmException garbage = assertThrows(HsmException.class,
                () -> token.unwrapKey(sessionA, kek, new byte[]{1, 2, 3}, "x", usages));
        assertEquals(HsmError.UNWRAPPING_FAILED, garbage.getError());

        // Other keys and sessions are completely undisturbed.
        assertArrayEquals(MESSAGE, token.decrypt(sessionB, target, goodCiphertext));
        String copy = token.unwrapKey(sessionB, kek, good, "still-ok", usages);
        assertArrayEquals(MESSAGE, token.decrypt(sessionB, copy, goodCiphertext));
        assertEquals(2, token.status().get("openSessions"));
    }

    @Test
    void failedUnwrapDoesNotCreatePartialKeyObjects(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kek = token.generateKey(session, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP, KeyUsage.UNWRAP));
        EnumSet<KeyUsage> usages = EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
        String target = token.generateKey(session, KeyType.AES, 128, "t", usages, true);
        byte[] wrapped = token.wrapKey(session, kek, target);
        int keyCountBefore = (int) token.status().get("keyCount");

        assertThrows(HsmException.class,
                () -> token.unwrapKey(session, kek, wrapped, "x", EnumSet.of(KeyUsage.SIGN)));
        assertThrows(HsmException.class,
                () -> token.unwrapKey(session, kek, new byte[]{9, 9}, "x", usages));

        assertEquals(keyCountBefore, token.status().get("keyCount"));
    }
}
