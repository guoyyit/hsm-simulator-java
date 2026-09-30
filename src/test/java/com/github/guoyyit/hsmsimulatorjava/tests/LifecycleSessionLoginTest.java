package com.github.guoyyit.hsmsimulatorjava.tests;

import com.github.guoyyit.hsmsimulatorjava.hsm.core.HsmToken;
import com.github.guoyyit.hsmsimulatorjava.hsm.exception.HsmException;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.HsmError;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.KeyType;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.KeyUsage;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.UserType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.EnumSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LifecycleSessionLoginTest {

    private HsmToken initializedToken(Path dir) {
        HsmToken token = new HsmToken(dir);
        token.initializeToken("so-pin", "user-pin", "test-token");
        return token;
    }

    @Test
    void tokenStartsUninitializedAndRejectsOperations(@TempDir Path dir) {
        HsmToken token = new HsmToken(dir);
        assertFalse(token.isInitialized());
        HsmException ex = assertThrows(HsmException.class, token::openSession);
        assertEquals(HsmError.TOKEN_NOT_INITIALIZED, ex.getError());
    }

    @Test
    void initializeCreatesSoAndUserRoles(@TempDir Path dir) {
        HsmToken token = initializedToken(dir);
        assertTrue(token.isInitialized());
        assertFalse(token.isLocked());
        long session = token.openSession();
        token.login(session, UserType.USER, "user-pin");
        assertEquals(UserType.USER, token.currentRole(session));
    }

    @Test
    void cannotInitializeTwice(@TempDir Path dir) {
        HsmToken token = initializedToken(dir);
        HsmException ex = assertThrows(HsmException.class,
                () -> token.initializeToken("so-pin", "user-pin", "again"));
        assertEquals(HsmError.TOKEN_ALREADY_INITIALIZED, ex.getError());
    }

    @Test
    void sessionsHaveIndependentLoginState(@TempDir Path dir) {
        HsmToken token = initializedToken(dir);
        long sessionA = token.openSession();
        long sessionB = token.openSession();
        token.login(sessionA, UserType.USER, "user-pin");

        assertNull(token.currentRole(sessionB));
        HsmException ex = assertThrows(HsmException.class,
                () -> token.generateKey(sessionB, KeyType.AES, 128, "k",
                        EnumSet.of(KeyUsage.ENCRYPT)));
        assertEquals(HsmError.NOT_LOGGED_IN, ex.getError());

        token.closeSession(sessionA);
        long sessionC = token.openSession();
        assertNull(token.currentRole(sessionC));
        assertThrows(HsmException.class, () -> token.currentRole(sessionA));
    }

    @Test
    void lockedTokenRejectsEverythingExceptUnlockAndStatus(@TempDir Path dir) {
        HsmToken token = initializedToken(dir);
        long soSession = token.openSession();
        token.login(soSession, UserType.SO, "so-pin");
        token.lock(soSession);
        assertTrue(token.isLocked());

        assertThrows(HsmException.class, token::openSession);
        HsmException whileLocked = assertThrows(HsmException.class,
                () -> token.getKeyInfo(soSession, "anything"));
        assertEquals(HsmError.TOKEN_LOCKED, whileLocked.getError());

        token.unlock("so-pin");
        assertFalse(token.isLocked());
        assertEquals(0, token.status().get("userFailCount"));
        assertFalse((Boolean) token.status().get("userPinLocked"));
    }

    @Test
    void badUserPinAccumulatesAndLocksAfterThreshold(@TempDir Path dir) {
        HsmToken token = initializedToken(dir);
        long session = token.openSession();
        assertBadPin(token, session, UserType.USER, "wrong", HsmError.PIN_INCORRECT);
        assertBadPin(token, session, UserType.USER, "wrong", HsmError.PIN_INCORRECT);
        assertBadPin(token, session, UserType.USER, "wrong", HsmError.PIN_LOCKED);

        HsmException evenWithCorrectPin = assertThrows(HsmException.class,
                () -> token.login(session, UserType.USER, "user-pin"));
        assertEquals(HsmError.PIN_LOCKED, evenWithCorrectPin.getError());

        token.unlock("so-pin");
        long fresh = token.openSession();
        token.login(fresh, UserType.USER, "user-pin");
        assertEquals(UserType.USER, token.currentRole(fresh));
    }

    @Test
    void soAndUserFailureCountersAreSeparate(@TempDir Path dir) {
        HsmToken token = initializedToken(dir);
        long session = token.openSession();
        assertBadPin(token, session, UserType.USER, "wrong", HsmError.PIN_INCORRECT);
        token.login(session, UserType.SO, "so-pin");
        assertEquals(UserType.SO, token.currentRole(session));
    }

    @Test
    void soBadPinAlsoLocksAfterThreshold(@TempDir Path dir) {
        HsmToken token = initializedToken(dir);
        long session = token.openSession();
        assertBadPin(token, session, UserType.SO, "wrong", HsmError.PIN_INCORRECT);
        assertBadPin(token, session, UserType.SO, "wrong", HsmError.PIN_INCORRECT);
        assertBadPin(token, session, UserType.SO, "wrong", HsmError.PIN_LOCKED);
        assertTrue((Boolean) token.status().get("soPinLocked"));
        assertEquals(0, token.status().get("userFailCount"));
        HsmException unlock = assertThrows(HsmException.class, () -> token.unlock("so-pin"));
        assertEquals(HsmError.PIN_LOCKED, unlock.getError());
    }

    @Test
    void concurrentSessionsAreIsolatedUnderParallelUse(@TempDir Path dir) throws Exception {
        HsmToken token = initializedToken(dir);
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger ok = new AtomicInteger();
        try {
            for (int i = 0; i < threads; i++) {
                pool.submit(() -> {
                    start.await();
                    long session = token.openSession();
                    token.login(session, UserType.USER, "user-pin");
                    String keyId = token.generateKey(session, KeyType.AES, 128,
                            "concurrent", EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT));
                    byte[] ciphertext = token.encrypt(session, keyId, new byte[]{1, 2, 3});
                    token.decrypt(session, keyId, ciphertext);
                    token.closeSession(session);
                    ok.incrementAndGet();
                    return null;
                });
            }
            start.countDown();
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        }
        assertEquals(threads, ok.get());
        assertEquals(0, token.status().get("openSessions"));
    }

    private void assertBadPin(HsmToken token, long session, UserType role, String pin, HsmError expected) {
        HsmException ex = assertThrows(HsmException.class,
                () -> token.login(session, role, pin));
        assertEquals(expected, ex.getError());
    }
}
