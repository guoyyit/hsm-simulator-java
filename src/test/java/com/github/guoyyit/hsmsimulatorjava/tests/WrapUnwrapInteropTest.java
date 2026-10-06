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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An unwrapped copy must be behaviorally equivalent to its source key in
 * both directions: ciphertext and signatures cross-verify between the two
 * distinct key objects, and every constraint attribute is preserved exactly.
 */
class WrapUnwrapInteropTest {

    private static final byte[] MESSAGE = "interop-payload".getBytes(StandardCharsets.UTF_8);

    private HsmToken readyToken(Path dir) {
        HsmToken token = new HsmToken(dir);
        token.initializeToken("so-pin", "user-pin", "interop");
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
    void aesCiphertextCrossesBetweenSourceAndCopyInBothDirections(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kek = kek(token, session);
        EnumSet<KeyUsage> usages = EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
        String source = token.generateKey(session, KeyType.AES, 256, "src", usages, true);

        // Source encrypts before the copy even exists.
        byte[] fromSource = token.encrypt(session, source, MESSAGE);
        String copy = token.unwrapKey(session, kek, token.wrapKey(session, kek, source), "copy", usages);

        // Copy (a different key object) decrypts the source's ciphertext.
        assertArrayEquals(MESSAGE, token.decrypt(session, copy, fromSource));
        // Copy encrypts, source decrypts.
        byte[] fromCopy = token.encrypt(session, copy, MESSAGE);
        assertArrayEquals(MESSAGE, token.decrypt(session, source, fromCopy));
    }

    @Test
    void rsaSignaturesCrossVerifyBetweenSourceAndCopyInBothDirections(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kek = kek(token, session);
        EnumSet<KeyUsage> usages = EnumSet.of(KeyUsage.SIGN, KeyUsage.VERIFY);
        String source = token.generateKey(session, KeyType.RSA, 2048, "src", usages, true);

        byte[] sourceSignature = token.sign(session, source, MESSAGE);
        String copy = token.unwrapKey(session, kek, token.wrapKey(session, kek, source), "copy", usages);

        // Signature made by the source verifies under the copy.
        assertTrue(token.verify(session, copy, MESSAGE, sourceSignature));
        // Signature made by the copy verifies under the source.
        byte[] copySignature = token.sign(session, copy, MESSAGE);
        assertTrue(token.verify(session, source, MESSAGE, copySignature));
    }

    @Test
    void rsaCiphertextCrossesBetweenSourceAndCopy(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kek = kek(token, session);
        EnumSet<KeyUsage> usages = EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
        String source = token.generateKey(session, KeyType.RSA, 2048, "src", usages, true);

        byte[] fromSource = token.encrypt(session, source, MESSAGE);
        String copy = token.unwrapKey(session, kek, token.wrapKey(session, kek, source), "copy", usages);
        assertArrayEquals(MESSAGE, token.decrypt(session, copy, fromSource));
        byte[] fromCopy = token.encrypt(session, copy, MESSAGE);
        assertArrayEquals(MESSAGE, token.decrypt(session, source, fromCopy));
    }

    @Test
    void unwrappedCopyMatchesEveryConstraintOfTheSource(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kek = kek(token, session);
        EnumSet<KeyUsage> usages = EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.WRAP);
        byte[] raw = new com.github.guoyyit.hsmsimulatorjava.hsm.crypto.CryptoEngine().generateAesKey(192);
        String source = token.importKey(session, KeyType.AES, "imported-src", usages,
                true, true, raw, null);

        String copy = token.unwrapKey(session, kek, token.wrapKey(session, kek, source), "copy", usages);
        Map<String, Object> src = token.getKeyInfo(session, source);
        Map<String, Object> dst = token.getKeyInfo(session, copy);

        assertEquals(src.get("keyType"), dst.get("keyType"));
        assertEquals(src.get("keyBits"), dst.get("keyBits"));
        assertEquals(src.get("usages"), dst.get("usages"));
        assertEquals(src.get("sensitive"), dst.get("sensitive"));
        assertEquals(src.get("extractable"), dst.get("extractable"));

        // The copy cannot be used beyond the preserved usage set either:
        // it lacks UNWRAP, so using it as an unwrap-kek fails on usage grounds.
        HsmException usage = assertThrows(HsmException.class,
                () -> token.unwrapKey(session, copy,
                        token.wrapKey(session, kek, source), "x", usages));
        assertEquals(HsmError.KEY_USAGE_VIOLATION, usage.getError());
    }

    @Test
    void interopSurvivesRestartOnBothSides(@TempDir Path dir) {
        HsmToken before = readyToken(dir);
        long session = userSession(before);
        String kek = kek(before, session);
        EnumSet<KeyUsage> aesUsages = EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
        EnumSet<KeyUsage> rsaUsages = EnumSet.of(KeyUsage.SIGN, KeyUsage.VERIFY);
        String aesSource = before.generateKey(session, KeyType.AES, 128, "aes-src", aesUsages, true);
        String rsaSource = before.generateKey(session, KeyType.RSA, 2048, "rsa-src", rsaUsages, true);
        byte[] aesWrapped = before.wrapKey(session, kek, aesSource);
        byte[] rsaWrapped = before.wrapKey(session, kek, rsaSource);
        byte[] ciphertextBeforeRestart = before.encrypt(session, aesSource, MESSAGE);
        byte[] signatureBeforeRestart = before.sign(session, rsaSource, MESSAGE);

        // Unwrap after a restart: the envelopes produced before the restart
        // still open and the copies interoperate with the sources.
        HsmToken after = new HsmToken(dir);
        long s2 = userSession(after);
        String aesCopy = after.unwrapKey(s2, kek, aesWrapped, "aes-copy", aesUsages);
        String rsaCopy = after.unwrapKey(s2, kek, rsaWrapped, "rsa-copy", rsaUsages);

        assertArrayEquals(MESSAGE, after.decrypt(s2, aesCopy, ciphertextBeforeRestart));
        assertTrue(after.verify(s2, rsaCopy, MESSAGE, signatureBeforeRestart));

        byte[] ciphertextAfterRestart = after.encrypt(s2, aesCopy, MESSAGE);
        byte[] signatureAfterRestart = after.sign(s2, rsaCopy, MESSAGE);

        // And once more across another restart, in the opposite direction.
        HsmToken third = new HsmToken(dir);
        long s3 = userSession(third);
        assertArrayEquals(MESSAGE, third.decrypt(s3, aesSource, ciphertextAfterRestart));
        assertTrue(third.verify(s3, rsaSource, MESSAGE, signatureAfterRestart));
    }
}
