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
import java.nio.file.Path;
import java.util.EnumSet;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyLifecycleUsageTest {

    private static final byte[] MESSAGE = "hello-hsm".getBytes(StandardCharsets.UTF_8);

    private HsmToken readyToken(Path dir) {
        HsmToken token = new HsmToken(dir);
        token.initializeToken("so-pin", "user-pin", "test-token");
        long session = token.openSession();
        token.login(session, UserType.USER, "user-pin");
        return token;
    }

    private long userSession(HsmToken token) {
        long session = token.openSession();
        token.login(session, UserType.USER, "user-pin");
        return session;
    }

    @Test
    void aesEncryptDecryptRoundTrip(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String keyId = token.generateKey(session, KeyType.AES, 256, "aes",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT));
        byte[] ciphertext = token.encrypt(session, keyId, MESSAGE);
        assertFalse(new String(ciphertext, StandardCharsets.UTF_8).contains("hello-hsm"));
        assertArrayEquals(MESSAGE, token.decrypt(session, keyId, ciphertext));
    }

    @Test
    void rsaSignVerifyRoundTrip(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String keyId = token.generateKey(session, KeyType.RSA, 2048, "rsa",
                EnumSet.of(KeyUsage.SIGN, KeyUsage.VERIFY));
        byte[] signature = token.sign(session, keyId, MESSAGE);
        assertTrue(token.verify(session, keyId, MESSAGE, signature));
        assertFalse(token.verify(session, keyId, "other".getBytes(StandardCharsets.UTF_8), signature));
    }

    @Test
    void digestIsIndependentOfKeys(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        assertArrayEquals(new CryptoEngine().sha256(MESSAGE), token.digest(session, MESSAGE));
    }

    @Test
    void operationRejectedWhenKeyUsageNotAllowed(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String encryptOnly = token.generateKey(session, KeyType.AES, 128, "enc",
                EnumSet.of(KeyUsage.ENCRYPT));
        byte[] ciphertext = token.encrypt(session, encryptOnly, MESSAGE);

        HsmException ex = assertThrows(HsmException.class,
                () -> token.decrypt(session, encryptOnly, ciphertext));
        assertEquals(HsmError.KEY_USAGE_VIOLATION, ex.getError());

        String signKey = token.generateKey(session, KeyType.RSA, 2048, "sig",
                EnumSet.of(KeyUsage.SIGN, KeyUsage.VERIFY));
        HsmException encryptWithSignKey = assertThrows(HsmException.class,
                () -> token.encrypt(session, signKey, MESSAGE));
        assertEquals(HsmError.KEY_USAGE_VIOLATION, encryptWithSignKey.getError());
    }

    @Test
    void keyInfoNeverExposesPlaintextMaterial(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String keyId = token.generateKey(session, KeyType.AES, 256, "secret",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.WRAP, KeyUsage.UNWRAP));
        Map<String, Object> info = token.getKeyInfo(session, keyId);
        assertTrue((Boolean) info.get("sensitive"));
        assertFalse((Boolean) info.get("extractable"));
        assertFalse(info.containsKey("material"));
    }

    @Test
    void importedAesKeyBehavesLikeGeneratedKey(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        byte[] raw = new CryptoEngine().generateAesKey(128);
        String keyId = token.importKey(session, KeyType.AES, "imported",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), true, raw, null);
        byte[] ciphertext = token.encrypt(session, keyId, MESSAGE);
        assertArrayEquals(MESSAGE, token.decrypt(session, keyId, ciphertext));
    }

    @Test
    void destroyedKeyFailsEveryUse(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String keyId = token.generateKey(session, KeyType.AES, 128, "doomed",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.WRAP));
        token.destroyKey(session, keyId);

        HsmException get = assertThrows(HsmException.class,
                () -> token.getKeyInfo(session, keyId));
        assertEquals(HsmError.KEY_DESTROYED, get.getError());
        HsmException use = assertThrows(HsmException.class,
                () -> token.encrypt(session, keyId, MESSAGE));
        assertEquals(HsmError.KEY_DESTROYED, use.getError());
        HsmException wrap = assertThrows(HsmException.class,
                () -> token.wrapKey(session, keyId, keyId));
        assertEquals(HsmError.KEY_DESTROYED, wrap.getError());
    }

    @Test
    void unknownKeyHasDistinguishableError(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        HsmException ex = assertThrows(HsmException.class,
                () -> token.encrypt(session, "missing", MESSAGE));
        assertEquals(HsmError.KEY_NOT_FOUND, ex.getError());
        assertNotNull(ex.getMessage());
    }
}
