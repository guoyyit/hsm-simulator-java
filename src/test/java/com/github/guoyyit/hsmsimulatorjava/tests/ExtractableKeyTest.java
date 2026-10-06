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

import java.nio.file.Path;
import java.util.EnumSet;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The extractable attribute governs wrapping export: it is settable at
 * generation/import, defaults to non-extractable, persists across restarts,
 * is reported by key info and is preserved on unwrapped copies.
 */
class ExtractableKeyTest {

    private HsmToken readyToken(Path dir) {
        HsmToken token = new HsmToken(dir);
        token.initializeToken("so-pin", "user-pin", "extractable");
        return token;
    }

    private long userSession(HsmToken token) {
        long session = token.openSession();
        token.login(session, UserType.USER, "user-pin");
        return session;
    }

    private String kek(HsmToken token, long session) {
        return token.generateKey(session, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP, KeyUsage.UNWRAP));
    }

    @Test
    void defaultIsNonExtractableForGenerateAndImport(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String generated = token.generateKey(session, KeyType.AES, 128, "gen",
                EnumSet.of(KeyUsage.ENCRYPT));
        String imported = token.importKey(session, KeyType.AES, "imp",
                EnumSet.of(KeyUsage.ENCRYPT), true, new CryptoEngine().generateAesKey(128), null);
        assertFalse((Boolean) token.getKeyInfo(session, generated).get("extractable"));
        assertFalse((Boolean) token.getKeyInfo(session, imported).get("extractable"));
    }

    @Test
    void nonExtractableKeyCannotBeWrappedWithDistinguishableReason(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kekId = kek(token, session);
        String sealed = token.generateKey(session, KeyType.AES, 128, "sealed",
                EnumSet.of(KeyUsage.ENCRYPT), false);

        HsmException ex = assertThrows(HsmException.class,
                () -> token.wrapKey(session, kekId, sealed));
        assertEquals(HsmError.KEY_NOT_EXTRACTABLE, ex.getError());
        assertNotEquals(HsmError.KEY_USAGE_VIOLATION, ex.getError());
        assertNotEquals(HsmError.KEY_NOT_FOUND, ex.getError());
        assertNotEquals(HsmError.KEY_DESTROYED, ex.getError());

        // The rejected wrap changes nothing: the key is still fully usable.
        assertEquals("sealed", token.getKeyInfo(session, sealed).get("label"));
    }

    @Test
    void explicitExtractableKeysCanBeWrapped(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kekId = kek(token, session);
        String generated = token.generateKey(session, KeyType.AES, 128, "gen",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), true);
        String imported = token.importKey(session, KeyType.AES, "imp",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), true,
                new CryptoEngine().generateAesKey(128), null, true);
        assertTrue((Boolean) token.getKeyInfo(session, generated).get("extractable"));
        assertTrue((Boolean) token.getKeyInfo(session, imported).get("extractable"));
        token.wrapKey(session, kekId, generated);
        token.wrapKey(session, kekId, imported);
    }

    @Test
    void unwrappedCopyKeepsExtractabilityOfSource(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kekId = kek(token, session);
        String source = token.generateKey(session, KeyType.AES, 128, "source",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), true);

        byte[] wrapped = token.wrapKey(session, kekId, source);
        String copyId = token.unwrapKey(session, kekId, wrapped, "copy", null);

        Map<String, Object> copy = token.getKeyInfo(session, copyId);
        assertEquals(true, copy.get("extractable"));
        assertEquals(true, copy.get("sensitive"));
        // The copy is itself wrappable, proving the attribute survived.
        byte[] rewrapped = token.wrapKey(session, kekId, copyId);
        String grandchild = token.unwrapKey(session, kekId, rewrapped, "grandchild", null);
        assertEquals(true, token.getKeyInfo(session, grandchild).get("extractable"));
    }

    @Test
    void extractabilitySurvivesRestart(@TempDir Path dir) {
        HsmToken before = readyToken(dir);
        long session = userSession(before);
        String kekId = kek(before, session);
        String sealed = before.generateKey(session, KeyType.AES, 128, "sealed",
                EnumSet.of(KeyUsage.ENCRYPT), false);
        String open = before.generateKey(session, KeyType.AES, 128, "open",
                EnumSet.of(KeyUsage.ENCRYPT), true);

        HsmToken after = new HsmToken(dir);
        long restarted = userSession(after);
        assertFalse((Boolean) after.getKeyInfo(restarted, sealed).get("extractable"));
        assertTrue((Boolean) after.getKeyInfo(restarted, open).get("extractable"));

        HsmException ex = assertThrows(HsmException.class,
                () -> after.wrapKey(restarted, kekId, sealed));
        assertEquals(HsmError.KEY_NOT_EXTRACTABLE, ex.getError());
        after.wrapKey(restarted, kekId, open);
    }

    @Test
    void destroyedOrMissingKeysKeepTheirOwnReasonsWhenWrapping(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kekId = kek(token, session);
        String doomed = token.generateKey(session, KeyType.AES, 128, "doomed",
                EnumSet.of(KeyUsage.ENCRYPT), true);
        token.destroyKey(session, doomed);

        HsmException destroyed = assertThrows(HsmException.class,
                () -> token.wrapKey(session, kekId, doomed));
        assertEquals(HsmError.KEY_DESTROYED, destroyed.getError());
        HsmException missing = assertThrows(HsmException.class,
                () -> token.wrapKey(session, kekId, "no-such-key"));
        assertEquals(HsmError.KEY_NOT_FOUND, missing.getError());
    }
}
