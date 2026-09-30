package com.github.guoyyit.hsmsimulatorjava.hsm;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class WrapRoundTripTest {

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
    void wrappedAesKeyUnwrapsToEquivalentKey() {
        KeyObject wrapping = service.generateKey(session, KeyType.RSA, "kek",
                Set.of(KeyUsage.WRAP, KeyUsage.UNWRAP), true);
        KeyObject target = service.generateKey(session, KeyType.AES, "data-key",
                Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), true);

        byte[] plaintext = "round-trip".getBytes();
        byte[] ciphertext = service.encrypt(session, target.getId(), plaintext);

        WrappedKey wrapped = service.wrapKey(session, wrapping.getId(), target.getId());
        KeyObject restored = service.unwrapKey(session, wrapping.getId(), wrapped);

        assertNotEquals(target.getId(), restored.getId());
        assertEquals(target.getKeyType(), restored.getKeyType());
        assertEquals(target.getLabel(), restored.getLabel());
        assertEquals(target.getUsages(), restored.getUsages());
        assertEquals(target.isExtractable(), restored.isExtractable());
        assertEquals(target.isSensitive(), restored.isSensitive());

        assertArrayEquals(plaintext,
                service.decrypt(session, restored.getId(), ciphertext));
        byte[] second = service.encrypt(session, restored.getId(), plaintext);
        assertArrayEquals(plaintext,
                service.decrypt(session, target.getId(), second));
    }

    @Test
    void wrapRequiresWrapUsageAndExtractability() {
        KeyObject noWrap = service.generateKey(session, KeyType.RSA, "no-wrap",
                Set.of(KeyUsage.UNWRAP), true);
        KeyObject target = service.generateKey(session, KeyType.AES, "target",
                Set.of(KeyUsage.ENCRYPT), true);

        HsmException usageError = assertThrows(HsmException.class,
                () -> service.wrapKey(session, noWrap.getId(), target.getId()));
        assertEquals(HsmErrorCode.USAGE_NOT_ALLOWED, usageError.getCode());

        KeyObject kek = service.generateKey(session, KeyType.RSA, "kek",
                Set.of(KeyUsage.WRAP, KeyUsage.UNWRAP), true);
        KeyObject nonExtractable = service.generateKey(session, KeyType.AES, "locked",
                Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), false);
        HsmException extractError = assertThrows(HsmException.class,
                () -> service.wrapKey(session, kek.getId(), nonExtractable.getId()));
        assertEquals(HsmErrorCode.KEY_NOT_EXTRACTABLE, extractError.getCode());
    }

    @Test
    void unwrapRequiresUnwrapUsage() {
        KeyObject wrapOnly = service.generateKey(session, KeyType.RSA, "wrap-only",
                Set.of(KeyUsage.WRAP), true);
        KeyObject kek = service.generateKey(session, KeyType.RSA, "kek",
                Set.of(KeyUsage.WRAP, KeyUsage.UNWRAP), true);
        KeyObject target = service.generateKey(session, KeyType.AES, "target",
                Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), true);
        WrappedKey wrapped = service.wrapKey(session, kek.getId(), target.getId());

        HsmException error = assertThrows(HsmException.class,
                () -> service.unwrapKey(session, wrapOnly.getId(), wrapped));
        assertEquals(HsmErrorCode.USAGE_NOT_ALLOWED, error.getCode());
    }

    @Test
    void wrappedPayloadRejectsTampering() {
        KeyObject kek = service.generateKey(session, KeyType.RSA, "kek",
                Set.of(KeyUsage.WRAP, KeyUsage.UNWRAP), true);
        KeyObject target = service.generateKey(session, KeyType.AES, "target",
                Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), true);
        WrappedKey wrapped = service.wrapKey(session, kek.getId(), target.getId());

        byte[] tampered = wrapped.ciphertext().clone();
        tampered[0] ^= 0x01;
        WrappedKey corrupted = new WrappedKey(wrapped.version(), wrapped.alg(),
                wrapped.wrappingKeyId(), wrapped.iv(), wrapped.encryptedCek(), tampered);

        assertThrows(HsmException.class,
                () -> service.unwrapKey(session, kek.getId(), corrupted));
    }
}
