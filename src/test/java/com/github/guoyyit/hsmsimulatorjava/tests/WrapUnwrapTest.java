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

class WrapUnwrapTest {

    private static final byte[] MESSAGE = "wrap-me".getBytes(StandardCharsets.UTF_8);

    private HsmToken readyToken(Path dir) {
        HsmToken token = new HsmToken(dir);
        token.initializeToken("so-pin", "user-pin", "test-token");
        return token;
    }

    private long userSession(HsmToken token) {
        long session = token.openSession();
        token.login(session, UserType.USER, "user-pin");
        return session;
    }

    @Test
    void aesKeyWrapUnwrapPreservesMaterialAndUsages(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kekId = token.generateKey(session, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP, KeyUsage.UNWRAP));
        EnumSet<KeyUsage> usages = EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
        String targetId = token.generateKey(session, KeyType.AES, 128, "target", usages);
        byte[] ciphertextBefore = token.encrypt(session, targetId, MESSAGE);

        byte[] wrapped = token.wrapKey(session, kekId, targetId);
        String copyId = token.unwrapKey(session, kekId, wrapped, "target-copy", usages);

        Map<String, Object> copy = token.getKeyInfo(session, copyId);
        assertEquals("AES", copy.get("keyType"));
        assertEquals(128, copy.get("keyBits"));
        assertEquals(usages, parseUsages(copy));

        byte[] copyCiphertext = token.encrypt(session, copyId, MESSAGE);
        assertArrayEquals(MESSAGE, token.decrypt(session, copyId, copyCiphertext));
        assertArrayEquals(MESSAGE, token.decrypt(session, targetId, ciphertextBefore));
    }

    @Test
    void rsaKeyWrapUnwrapPreservesSigningBehavior(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kekId = token.generateKey(session, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP, KeyUsage.UNWRAP));
        EnumSet<KeyUsage> usages = EnumSet.of(KeyUsage.SIGN, KeyUsage.VERIFY);
        String targetId = token.generateKey(session, KeyType.RSA, 2048, "rsa-target", usages);
        byte[] signature = token.sign(session, targetId, MESSAGE);

        byte[] wrapped = token.wrapKey(session, kekId, targetId);
        String copyId = token.unwrapKey(session, kekId, wrapped, "rsa-copy", usages);

        assertEquals(usages, parseUsages(token.getKeyInfo(session, copyId)));
        assertTrue(token.verify(session, copyId, MESSAGE, signature));
        byte[] copySignature = token.sign(session, copyId, MESSAGE);
        assertTrue(token.verify(session, targetId, MESSAGE, copySignature));
    }

    @Test
    void wrapAndUnwrapRequireMatchingUsage(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String noWrap = token.generateKey(session, KeyType.AES, 256, "no-wrap",
                EnumSet.of(KeyUsage.ENCRYPT));
        String target = token.generateKey(session, KeyType.AES, 128, "target",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT));

        HsmException wrap = assertThrows(HsmException.class,
                () -> token.wrapKey(session, noWrap, target));
        assertEquals(HsmError.KEY_USAGE_VIOLATION, wrap.getError());

        String kekId = token.generateKey(session, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP));
        byte[] wrapped = token.wrapKey(session, kekId, target);
        HsmException unwrap = assertThrows(HsmException.class,
                () -> token.unwrapKey(session, kekId, wrapped, "x",
                        EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)));
        assertEquals(HsmError.KEY_USAGE_VIOLATION, unwrap.getError());
    }

    @Test
    void tamperedWrappedBlobIsRejected(@TempDir Path dir) throws Exception {
        HsmToken token = readyToken(dir);
        long session = userSession(token);
        String kekId = token.generateKey(session, KeyType.AES, 256, "kek",
                EnumSet.of(KeyUsage.WRAP, KeyUsage.UNWRAP));
        String target = token.generateKey(session, KeyType.AES, 128, "target",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT));
        byte[] wrapped = token.wrapKey(session, kekId, target);
        com.fasterxml.jackson.databind.ObjectMapper mapper =
                new com.fasterxml.jackson.databind.ObjectMapper();
        Map<String, String> envelope = mapper.readValue(wrapped,
                new com.fasterxml.jackson.core.type.TypeReference<>() {
                });
        byte[] inner = java.util.Base64.getDecoder().decode(envelope.get("wrapped"));
        inner[inner.length - 1] ^= 0x01;
        envelope.put("wrapped", java.util.Base64.getEncoder().encodeToString(inner));
        byte[] tampered = mapper.writeValueAsBytes(envelope);
        HsmException ex = assertThrows(HsmException.class,
                () -> token.unwrapKey(session, kekId, tampered, "x",
                        EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)));
        assertEquals(HsmError.UNWRAPPING_FAILED, ex.getError());
    }

    @SuppressWarnings("unchecked")
    private EnumSet<KeyUsage> parseUsages(Map<String, Object> info) {
        EnumSet<KeyUsage> usages = EnumSet.noneOf(KeyUsage.class);
        for (String name : (java.util.List<String>) info.get("usages")) {
            usages.add(KeyUsage.valueOf(name));
        }
        return usages;
    }
}
