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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * One-shot cleanup of every session: all outstanding handles die, nothing
 * else about the token changes, and fresh sessions work immediately.
 */
class SessionCleanupTest {

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
    void closeAllSessionsInvalidatesEveryHandle(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long first = userSession(token);
        long second = userSession(token);
        long anonymous = token.openSession();
        String keyId = token.generateKey(first, KeyType.AES, 128, "k",
                EnumSet.of(KeyUsage.ENCRYPT));
        assertEquals(3, token.status().get("openSessions"));

        token.closeAllSessions();
        assertEquals(0, token.status().get("openSessions"));

        for (long handle : new long[]{first, second, anonymous}) {
            HsmException ex = assertThrows(HsmException.class,
                    () -> token.getKeyInfo(handle, keyId));
            assertEquals(HsmError.SESSION_HANDLE_INVALID, ex.getError());
        }

        // Clients must reopen and log in again; then everything works.
        long fresh = token.openSession();
        token.login(fresh, UserType.USER, "user-pin");
        assertEquals("k", token.getKeyInfo(fresh, keyId).get("label"));
    }

    @Test
    void cleanupTouchesOnlySessionState(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long probe = token.openSession();
        assertThrows(HsmException.class, () -> token.login(probe, UserType.USER, "bad"));
        assertEquals(1, token.status().get("userFailCount"));
        long user = userSession(token);
        String keyId = token.generateKey(user, KeyType.AES, 128, "k",
                EnumSet.of(KeyUsage.ENCRYPT), false);
        long so = token.openSession();
        token.login(so, UserType.SO, "so-pin");
        token.lock(so);
        assertTrue(token.isLocked());

        // Cleanup while locked: allowed, and neither the lock flag nor the
        // PIN failure counter nor the key objects may move.
        Object failCountBefore = token.status().get("userFailCount");
        token.closeAllSessions();
        assertTrue(token.isLocked());
        assertEquals(failCountBefore, token.status().get("userFailCount"));
        assertEquals(1, token.status().get("keyCount"));
        assertEquals(0, token.status().get("openSessions"));

        // Unlock resets the counter by its own documented semantics; the key
        // and its constraints are exactly as before the cleanup.
        token.unlock("so-pin");
        assertFalse(token.isLocked());
        assertEquals(0, token.status().get("userFailCount"));
        long fresh = userSession(token);
        assertFalse((Boolean) token.getKeyInfo(fresh, keyId).get("extractable"));
    }

    @Test
    void singleCloseAndCleanupDoNotInterfere(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long a = userSession(token);
        long b = userSession(token);

        token.closeSession(a);
        assertThrows(HsmException.class, () -> token.currentRole(a));
        assertEquals(UserType.USER, token.currentRole(b));

        token.closeAllSessions();
        assertThrows(HsmException.class, () -> token.currentRole(b));

        // Closing an already-dead handle is a no-op, not an error.
        token.closeSession(a);
        token.closeAllSessions();
        assertEquals(0, token.status().get("openSessions"));
    }

    @Test
    void cleanupDoesNotAffectLaterSessions(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long before = userSession(token);
        token.closeAllSessions();

        long after = token.openSession();
        token.login(after, UserType.USER, "user-pin");
        String keyId = token.generateKey(after, KeyType.AES, 128, "k",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT));
        byte[] ciphertext = token.encrypt(after, keyId, new byte[]{7, 7});
        token.decrypt(after, keyId, ciphertext);
        assertThrows(HsmException.class, () -> token.currentRole(before));
    }
}
