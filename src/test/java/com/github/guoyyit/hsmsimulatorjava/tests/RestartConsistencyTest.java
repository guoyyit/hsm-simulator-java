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
 * Everything decided before a restart must still hold after it: role rules,
 * extractability, usage constraints, session-cleanup semantics and
 * source/copy interoperability of wrapped keys.
 */
class RestartConsistencyTest {

    private static final byte[] MESSAGE = "restart-interop".getBytes(StandardCharsets.UTF_8);

    private HsmToken readyToken(Path dir) {
        HsmToken token = new HsmToken(dir);
        token.initializeToken("so-pin", "user-pin", "restart");
        return token;
    }

    private long userSession(HsmToken token) {
        long session = token.openSession();
        token.login(session, UserType.USER, "user-pin");
        return session;
    }

    @Test
    void wrapBeforeRestartUnwrapsAfterRestartWithFullInterop(@TempDir Path dir) {
        HsmToken before = readyToken(dir);
        long session = userSession(before);
        String kekId = before.generateKey(session, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP, KeyUsage.UNWRAP));
        EnumSet<KeyUsage> usages = EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
        String targetId = before.generateKey(session, KeyType.AES, 128, "target", usages, true);
        byte[] ciphertextBefore = before.encrypt(session, targetId, MESSAGE);
        byte[] wrapped = before.wrapKey(session, kekId, targetId);

        // "Restart": a fresh token instance over the same data directory.
        HsmToken after = new HsmToken(dir);
        long restarted = userSession(after);
        String copyId = after.unwrapKey(restarted, kekId, wrapped, "copy", usages);

        Map<String, Object> copy = after.getKeyInfo(restarted, copyId);
        assertEquals("AES", copy.get("keyType"));
        assertEquals(128, copy.get("keyBits"));
        assertEquals(true, copy.get("extractable"));

        // The copy made after the restart opens pre-restart ciphertext and
        // interoperates with the source in both directions.
        assertArrayEquals(MESSAGE, after.decrypt(restarted, copyId, ciphertextBefore));
        byte[] copyCiphertext = after.encrypt(restarted, copyId, MESSAGE);
        assertArrayEquals(MESSAGE, after.decrypt(restarted, targetId, copyCiphertext));

        // And the interop survives yet another restart.
        HsmToken again = new HsmToken(dir);
        long third = userSession(again);
        assertArrayEquals(MESSAGE, again.decrypt(third, copyId, ciphertextBefore));
        assertArrayEquals(MESSAGE, again.decrypt(third, targetId, copyCiphertext));
    }

    @Test
    void extractabilityConstraintSurvivesRestart(@TempDir Path dir) {
        HsmToken before = readyToken(dir);
        long session = userSession(before);
        String kekId = before.generateKey(session, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP, KeyUsage.UNWRAP));
        String sealedId = before.generateKey(session, KeyType.AES, 128, "sealed",
                EnumSet.of(KeyUsage.ENCRYPT), false);
        String openId = before.generateKey(session, KeyType.AES, 128, "open",
                EnumSet.of(KeyUsage.ENCRYPT), true);

        HsmToken after = new HsmToken(dir);
        long restarted = userSession(after);
        assertFalse((Boolean) after.getKeyInfo(restarted, sealedId).get("extractable"));
        assertTrue((Boolean) after.getKeyInfo(restarted, openId).get("extractable"));

        HsmException ex = assertThrows(HsmException.class,
                () -> after.wrapKey(restarted, kekId, sealedId));
        assertEquals(HsmError.KEY_NOT_EXTRACTABLE, ex.getError());
        after.wrapKey(restarted, kekId, openId);
    }

    @Test
    void usageConstraintsSurviveRestart(@TempDir Path dir) {
        HsmToken before = readyToken(dir);
        long session = userSession(before);
        String encOnly = before.generateKey(session, KeyType.AES, 128, "enc-only",
                EnumSet.of(KeyUsage.ENCRYPT));
        byte[] ciphertext = before.encrypt(session, encOnly, MESSAGE);

        HsmToken after = new HsmToken(dir);
        long restarted = userSession(after);
        HsmException ex = assertThrows(HsmException.class,
                () -> after.decrypt(restarted, encOnly, ciphertext));
        assertEquals(HsmError.KEY_USAGE_VIOLATION, ex.getError());
    }

    @Test
    void sessionCleanupRulesAreUnaffectedByRestart(@TempDir Path dir) {
        HsmToken before = readyToken(dir);
        long session = userSession(before);
        String keyId = before.generateKey(session, KeyType.AES, 128, "k",
                EnumSet.of(KeyUsage.ENCRYPT));
        before.closeAllSessions();

        HsmToken after = new HsmToken(dir);
        // Old handles are meaningless after a restart; new login works and
        // the key created before the restart is intact.
        HsmException stale = assertThrows(HsmException.class,
                () -> after.getKeyInfo(session, keyId));
        assertEquals(HsmError.SESSION_HANDLE_INVALID, stale.getError());
        long fresh = userSession(after);
        assertEquals("k", after.getKeyInfo(fresh, keyId).get("label"));
        assertFalse(after.isLocked());
        assertEquals(0, after.status().get("userFailCount"));
    }

    @Test
    void roleRulesSurviveRestart(@TempDir Path dir) {
        HsmToken before = readyToken(dir);
        long user = userSession(before);
        String keyId = before.generateKey(user, KeyType.AES, 128, "k",
                EnumSet.of(KeyUsage.ENCRYPT));

        HsmToken after = new HsmToken(dir);
        long so = after.openSession();
        after.login(so, UserType.SO, "so-pin");
        HsmException ex = assertThrows(HsmException.class,
                () -> after.getKeyInfo(so, keyId));
        assertEquals(HsmError.ROLE_REQUIRED, ex.getError());
    }
}
