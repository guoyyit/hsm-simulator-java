package com.github.guoyyit.hsmsimulatorjava.hsm;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyUsageTest {

    @TempDir
    Path tempDir;

    private HsmService service;
    private String session;

    @BeforeEach
    void setUp() {
        new HsmService(tempDir).initToken("so-pin", "user-pin");
        service = new HsmService(tempDir);
        session = service.openSession();
        service.login(session, Role.USER, "user-pin");
    }

    @Test
    void signAndVerifyWithRsaKey() {
        KeyObject key = service.generateKey(session, KeyType.RSA, "sig",
                Set.of(KeyUsage.SIGN, KeyUsage.VERIFY), false);
        byte[] data = "message".getBytes();
        byte[] signature = service.sign(session, key.getId(), data);
        assertTrue(service.verify(session, key.getId(), data, signature));
        assertFalse(service.verify(session, key.getId(), "tampered".getBytes(), signature));
    }

    @Test
    void encryptAndDecryptWithAesKey() {
        KeyObject key = service.generateKey(session, KeyType.AES, "enc",
                Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), true);
        byte[] data = "secret-message".getBytes();
        byte[] ciphertext = service.encrypt(session, key.getId(), data);
        assertArrayEquals(data, service.decrypt(session, key.getId(), ciphertext));
    }

    @Test
    void usageMismatchIsRejectedWithDistinctCode() {
        KeyObject signOnly = service.generateKey(session, KeyType.RSA, "sign-only",
                Set.of(KeyUsage.SIGN), false);

        HsmException verifyError = assertThrows(HsmException.class,
                () -> service.verify(session, signOnly.getId(),
                        "d".getBytes(), "s".getBytes()));
        assertEquals(HsmErrorCode.USAGE_NOT_ALLOWED, verifyError.getCode());

        KeyObject encryptOnly = service.generateKey(session, KeyType.AES, "enc-only",
                Set.of(KeyUsage.ENCRYPT), true);
        HsmException decryptError = assertThrows(HsmException.class,
                () -> service.decrypt(session, encryptOnly.getId(), new byte[16]));
        assertEquals(HsmErrorCode.USAGE_NOT_ALLOWED, decryptError.getCode());
    }

    @Test
    void destroyedKeyCanNoLongerBeUsed() {
        KeyObject key = service.generateKey(session, KeyType.AES, "short-lived",
                Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), true);
        byte[] ciphertext = service.encrypt(session, key.getId(), "data".getBytes());

        service.destroyKey(session, key.getId());

        HsmException useError = assertThrows(HsmException.class,
                () -> service.decrypt(session, key.getId(), ciphertext));
        assertEquals(HsmErrorCode.KEY_NOT_FOUND, useError.getCode());
        assertThrows(HsmException.class, () -> service.getKey(session, key.getId()));
        assertFalse(service.listKeys(session).stream()
                .anyMatch(k -> k.getId().equals(key.getId())));
    }

    @Test
    void keyViewsNeverExposeSensitivePrivateMaterial() {
        KeyObject aes = service.generateKey(session, KeyType.AES, "secret",
                Set.of(KeyUsage.ENCRYPT), true);
        assertNull(aes.getPrivateMaterial());

        KeyObject rsa = service.generateKey(session, KeyType.RSA, "pair",
                Set.of(KeyUsage.SIGN, KeyUsage.VERIFY), false);
        assertNull(rsa.getPrivateMaterial());
        assertTrue(rsa.getPublicMaterial().length > 0);
    }

    @Test
    void operationsRequireUserRole() {
        service.logout(session);
        service.login(session, Role.SO, "so-pin");

        HsmException error = assertThrows(HsmException.class,
                () -> service.generateKey(session, KeyType.AES, "x",
                        Set.of(KeyUsage.ENCRYPT), true));
        assertEquals(HsmErrorCode.ACCESS_DENIED, error.getCode());
    }

    @Test
    void digestProducesSha256() {
        byte[] digest = service.digest(session, "abc".getBytes());
        assertEquals(32, digest.length);
        byte[] expected = bytes(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assertArrayEquals(expected, digest);
    }

    private static byte[] bytes(String hex) {
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(
                    hex.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }
}
