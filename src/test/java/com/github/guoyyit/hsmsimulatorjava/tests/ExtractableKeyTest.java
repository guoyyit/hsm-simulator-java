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
 * The extractable attribute governs whether a key may leave the token via
 * wrapping. It defaults to false, persists across restarts, shows up in key
 * info and is carried over to unwrapped copies.
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

    @Test
    void extractableDefaultsToFalseWhenNotSpecified(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String generated = token.generateKey(session, KeyType.AES, 128, "gen",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT));
        assertFalse((Boolean) token.getKeyInfo(session, generated).get("extractable"));

        byte[] raw = new CryptoEngine().generateAesKey(128);
        String imported = token.importKey(session, KeyType.AES, "imp",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), true, raw, null);
        assertFalse((Boolean) token.getKeyInfo(session, imported).get("extractable"));
    }

    @Test
    void nonExtractableKeyCannotBeWrappedWithDistinguishableReason(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kek = token.generateKey(session, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP, KeyUsage.UNWRAP));
        String sealed = token.generateKey(session, KeyType.AES, 128, "sealed",
                EnumSet.of(KeyUsage.ENCRYPT), false);

        HsmException ex = assertThrows(HsmException.class,
                () -> token.wrapKey(session, kek, sealed));
        assertEquals(HsmError.KEY_NOT_EXTRACTABLE, ex.getError());

        // Distinct from usage, existence and destruction failures.
        String noWrapUsage = token.generateKey(session, KeyType.AES, 256, "plain",
                EnumSet.of(KeyUsage.ENCRYPT), true);
        HsmException usage = assertThrows(HsmException.class,
                () -> token.wrapKey(session, noWrapUsage, sealed));
        assertEquals(HsmError.KEY_USAGE_VIOLATION, usage.getError());
        HsmException missing = assertThrows(HsmException.class,
                () -> token.wrapKey(session, kek, "no-such-key"));
        assertEquals(HsmError.KEY_NOT_FOUND, missing.getError());
        String doomed = token.generateKey(session, KeyType.AES, 128, "doomed",
                EnumSet.of(KeyUsage.ENCRYPT), true);
        token.destroyKey(session, doomed);
        HsmException destroyed = assertThrows(HsmException.class,
                () -> token.wrapKey(session, kek, doomed));
        assertEquals(HsmError.KEY_DESTROYED, destroyed.getError());

        assertNotEquals(ex.getError(), usage.getError());
        assertNotEquals(ex.getError(), missing.getError());
        assertNotEquals(ex.getError(), destroyed.getError());
    }

    @Test
    void extractableKeyWrapsAndCopyKeepsTheAttribute(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kek = token.generateKey(session, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP, KeyUsage.UNWRAP));
        EnumSet<KeyUsage> usages = EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
        String source = token.generateKey(session, KeyType.AES, 128, "source", usages, true);

        byte[] wrapped = token.wrapKey(session, kek, source);
        String copy = token.unwrapKey(session, kek, wrapped, "copy", usages);

        Map<String, Object> info = token.getKeyInfo(session, copy);
        assertTrue((Boolean) info.get("extractable"));
        // The copy is itself wrappable, proving the attribute survived.
        byte[] rewrapped = token.wrapKey(session, kek, copy);
        String grandchild = token.unwrapKey(session, kek, rewrapped, "grandchild", usages);
        assertTrue((Boolean) token.getKeyInfo(session, grandchild).get("extractable"));
    }

    @Test
    void importHonoursExplicitExtractableFlag(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kek = token.generateKey(session, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP, KeyUsage.UNWRAP));
        byte[] raw = new CryptoEngine().generateAesKey(128);
        EnumSet<KeyUsage> usages = EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);

        String extractable = token.importKey(session, KeyType.AES, "ext", usages,
                true, true, raw, null);
        assertTrue((Boolean) token.getKeyInfo(session, extractable).get("extractable"));
        byte[] wrapped = token.wrapKey(session, kek, extractable);
        String copy = token.unwrapKey(session, kek, wrapped, "ext-copy", usages);
        assertTrue((Boolean) token.getKeyInfo(session, copy).get("extractable"));

        String sealed = token.importKey(session, KeyType.AES, "sealed", usages,
                true, false, raw, null);
        HsmException ex = assertThrows(HsmException.class,
                () -> token.wrapKey(session, kek, sealed));
        assertEquals(HsmError.KEY_NOT_EXTRACTABLE, ex.getError());
    }

    @Test
    void extractableAttributeAndConstraintSurviveRestart(@TempDir Path dir) {
        HsmToken before = readyToken(dir);
        long session = userSession(before);
        String kek = before.generateKey(session, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP, KeyUsage.UNWRAP));
        String open = before.generateKey(session, KeyType.AES, 128, "open",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), true);
        String sealed = before.generateKey(session, KeyType.AES, 128, "sealed",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), false);

        HsmToken after = new HsmToken(dir);
        long restarted = userSession(after);
        assertTrue((Boolean) after.getKeyInfo(restarted, open).get("extractable"));
        assertFalse((Boolean) after.getKeyInfo(restarted, sealed).get("extractable"));

        // Constraint still enforced after restart.
        HsmException ex = assertThrows(HsmException.class,
                () -> after.wrapKey(restarted, kek, sealed));
        assertEquals(HsmError.KEY_NOT_EXTRACTABLE, ex.getError());

        // And an extractable key still wraps into an extractable copy.
        byte[] wrapped = after.wrapKey(restarted, kek, open);
        String copy = after.unwrapKey(restarted, kek, wrapped, "open-copy",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT));
        assertTrue((Boolean) after.getKeyInfo(restarted, copy).get("extractable"));

        HsmToken again = new HsmToken(dir);
        long third = userSession(again);
        assertTrue((Boolean) again.getKeyInfo(third, copy).get("extractable"));
    }
}
