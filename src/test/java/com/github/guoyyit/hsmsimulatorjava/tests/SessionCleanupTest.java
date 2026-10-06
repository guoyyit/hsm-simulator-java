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
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * One-shot cleanup of every session: all issued handles die, nothing else
 * about the token changes, and brand-new sessions work immediately.
 */
class SessionCleanupTest {

    private static final byte[] MESSAGE = "cleanup".getBytes(StandardCharsets.UTF_8);

    private HsmToken readyToken(Path dir) {
        HsmToken token = new HsmToken(dir);
        token.initializeToken("so-pin", "user-pin", "cleanup");
        return token;
    }

    private long userSession(HsmToken token) {
        long session = token.openSession();
        token.login(session, UserType.USER, "user-pin");
        return session;
    }

    @Test
    void cleanupInvalidatesEveryIssuedHandle(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long userA = userSession(token);
        long userB = userSession(token);
        long so = token.openSession();
        token.login(so, UserType.SO, "so-pin");
        long anonymous = token.openSession();
        assertEquals(4, token.status().get("openSessions"));

        int closed = token.closeAllSessions();
        assertEquals(4, closed);
        assertEquals(0, token.status().get("openSessions"));

        for (long handle : new long[]{userA, userB, so, anonymous}) {
            HsmException ex = assertThrows(HsmException.class,
                    () -> token.currentRole(handle));
            assertEquals(HsmError.SESSION_HANDLE_INVALID, ex.getError());
        }
    }

    @Test
    void cleanupLeavesTokenStateUntouched(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long user = userSession(token);
        String keyId = token.generateKey(user, KeyType.AES, 128, "survivor",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), true);
        byte[] ciphertext = token.encrypt(user, keyId, MESSAGE);

        // Accumulate some PIN failures so the counter is provably preserved.
        long probe = token.openSession();
        assertThrows(HsmException.class, () -> token.login(probe, UserType.USER, "bad"));
        assertEquals(1, token.status().get("userFailCount"));

        token.closeAllSessions();

        Map<String, Object> status = token.status();
        assertFalse((Boolean) status.get("locked"));
        assertEquals(1, status.get("userFailCount"));
        assertEquals(1, status.get("keyCount"));

        // A fresh session can log in and use the surviving key right away.
        long fresh = userSession(token);
        assertEquals("survivor", token.getKeyInfo(fresh, keyId).get("label"));
        assertArrayEquals(MESSAGE, token.decrypt(fresh, keyId, ciphertext));
    }

    @Test
    void cleanupDoesNotChangeLockStateAndWorksWhileLocked(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long so = token.openSession();
        token.login(so, UserType.SO, "so-pin");
        token.lock(so);

        int closed = token.closeAllSessions();
        assertTrue(closed >= 1);
        assertTrue(token.isLocked());

        token.unlock("so-pin");
        long fresh = userSession(token);
        assertEquals(UserType.USER, token.currentRole(fresh));
    }

    @Test
    void singleCloseAndCleanupDoNotInterfere(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long a = userSession(token);
        long b = userSession(token);
        long c = userSession(token);

        token.closeSession(b);
        assertEquals(UserType.USER, token.currentRole(a));
        assertEquals(UserType.USER, token.currentRole(c));
        HsmException ex = assertThrows(HsmException.class, () -> token.currentRole(b));
        assertEquals(HsmError.SESSION_HANDLE_INVALID, ex.getError());

        token.closeAllSessions();
        assertThrows(HsmException.class, () -> token.currentRole(a));
        assertThrows(HsmException.class, () -> token.currentRole(c));

        // Closing an already-cleaned handle is a no-op, and cleanup on an
        // empty table is harmless and repeatable.
        token.closeSession(a);
        assertEquals(0, token.closeAllSessions());

        long fresh = userSession(token);
        assertEquals(UserType.USER, token.currentRole(fresh));
    }

    @Test
    void cleanupFollowedByRestartKeepsKeysUsable(@TempDir Path dir) {
        HsmToken before = readyToken(dir);
        long user = userSession(before);
        String keyId = before.generateKey(user, KeyType.AES, 128, "durable",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT));
        byte[] ciphertext = before.encrypt(user, keyId, MESSAGE);
        before.closeAllSessions();

        HsmToken after = new HsmToken(dir);
        long fresh = userSession(after);
        assertArrayEquals(MESSAGE, after.decrypt(fresh, keyId, ciphertext));
    }
}
