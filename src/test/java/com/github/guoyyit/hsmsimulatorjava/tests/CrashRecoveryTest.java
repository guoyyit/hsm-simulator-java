package com.github.guoyyit.hsmsimulatorjava.tests;

import com.github.guoyyit.hsmsimulatorjava.hsm.core.HsmToken;
import com.github.guoyyit.hsmsimulatorjava.hsm.crypto.CryptoEngine;
import com.github.guoyyit.hsmsimulatorjava.hsm.exception.HsmException;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.HsmError;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.KeyType;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.KeyUsage;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.UserType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CrashRecoveryTest {

    private static final byte[] MESSAGE = "survive-restart".getBytes(StandardCharsets.UTF_8);

    private long loggedInUserSession(HsmToken token) {
        long session = token.openSession();
        token.login(session, UserType.USER, "user-pin");
        return session;
    }

    @Test
    void keysAndProtectedMaterialSurviveRestart(@TempDir Path dir) {
        HsmToken before = new HsmToken(dir);
        before.initializeToken("so-pin", "user-pin", "durable-token");
        long session = loggedInUserSession(before);
        String aesId = before.generateKey(session, KeyType.AES, 256, "aes",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT));
        String rsaId = before.generateKey(session, KeyType.RSA, 2048, "rsa",
                EnumSet.of(KeyUsage.SIGN, KeyUsage.VERIFY));
        byte[] ciphertext = before.encrypt(session, aesId, MESSAGE);
        byte[] signature = before.sign(session, rsaId, MESSAGE);

        HsmToken after = new HsmToken(dir);
        assertTrue(after.isInitialized());
        long restartedSession = loggedInUserSession(after);
        assertArrayEquals(MESSAGE, after.decrypt(restartedSession, aesId, ciphertext));
        assertTrue(after.verify(restartedSession, rsaId, MESSAGE, signature));
        assertEquals(EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT),
                ((java.util.List<String>) after.getKeyInfo(restartedSession, aesId).get("usages"))
                        .stream().map(KeyUsage::valueOf)
                        .collect(java.util.stream.Collectors.toCollection(
                                () -> EnumSet.noneOf(KeyUsage.class))));
    }

    @Test
    void pinFailureCounterSurvivesRestart(@TempDir Path dir) {
        HsmToken before = new HsmToken(dir);
        before.initializeToken("so-pin", "user-pin", "durable-token");
        long session = before.openSession();
        assertThrows(HsmException.class,
                () -> before.login(session, UserType.USER, "bad"));
        assertEquals(1, before.status().get("userFailCount"));

        HsmToken after = new HsmToken(dir);
        assertEquals(1, after.status().get("userFailCount"));
        long restarted = after.openSession();
        HsmException ex = assertThrows(HsmException.class,
                () -> after.login(restarted, UserType.USER, "still-bad"));
        assertEquals(HsmError.PIN_INCORRECT, ex.getError());
        assertEquals(2, after.status().get("userFailCount"));
    }

    @Test
    void pinLockoutSurvivesRestartAndClearsOnlyAfterSoUnlock(@TempDir Path dir) {
        HsmToken before = new HsmToken(dir);
        before.initializeToken("so-pin", "user-pin", "durable-token");
        long session = before.openSession();
        for (int i = 0; i < 3; i++) {
            assertThrows(HsmException.class,
                    () -> before.login(session, UserType.USER, "bad"));
        }
        assertTrue((Boolean) before.status().get("userPinLocked"));

        HsmToken after = new HsmToken(dir);
        assertTrue((Boolean) after.status().get("userPinLocked"));
        after.unlock("so-pin");
        assertEquals(0, after.status().get("userFailCount"));

        HsmToken finalToken = new HsmToken(dir);
        long fresh = finalToken.openSession();
        finalToken.login(fresh, UserType.USER, "user-pin");
        assertEquals(UserType.USER, finalToken.currentRole(fresh));
    }

    @Test
    void tokenLockAndDestroyedKeysSurviveRestart(@TempDir Path dir) {
        HsmToken before = new HsmToken(dir);
        before.initializeToken("so-pin", "user-pin", "durable-token");
        long userSession = loggedInUserSession(before);
        String keyId = before.generateKey(userSession, KeyType.AES, 128, "soon-destroyed",
                EnumSet.of(KeyUsage.ENCRYPT));
        before.destroyKey(userSession, keyId);
        long soSession = before.openSession();
        before.login(soSession, UserType.SO, "so-pin");
        before.lock(soSession);

        HsmToken after = new HsmToken(dir);
        assertTrue(after.isLocked());
        assertThrows(HsmException.class, after::openSession);
        after.unlock("so-pin");
        long restarted = loggedInUserSession(after);
        HsmException ex = assertThrows(HsmException.class,
                () -> after.encrypt(restarted, keyId, MESSAGE));
        assertEquals(HsmError.KEY_DESTROYED, ex.getError());
    }

    @Test
    void snapshotFileIsSingleAtomicJsonState(@TempDir Path dir) throws Exception {
        HsmToken token = new HsmToken(dir);
        token.initializeToken("so-pin", "user-pin", "durable-token");
        long session = loggedInUserSession(token);
        token.generateKey(session, KeyType.AES, 128, "k",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT));
        try (java.util.stream.Stream<Path> files = Files.list(dir)) {
            assertTrue(files.anyMatch(path -> path.getFileName().toString().equals("token.json")));
        }
        HsmToken reread = new HsmToken(dir);
        assertTrue(reread.isInitialized());
    }

    @Test
    void digestIsStillAvailableAfterRestart(@TempDir Path dir) {
        HsmToken token = new HsmToken(dir);
        token.initializeToken("so-pin", "user-pin", "durable-token");
        long session = loggedInUserSession(token);
        byte[] digest = token.digest(session, MESSAGE);
        HsmToken after = new HsmToken(dir);
        assertArrayEquals(digest, after.digest(loggedInUserSession(after), MESSAGE));
        assertEquals(32, digest.length);
    }
}
