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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Key-object management and cryptographic operations are USER-only. An SO
 * session must be rejected with {@link HsmError#ROLE_REQUIRED}, a reason
 * distinct from not-logged-in, invalid-handle and token-locked failures.
 */
class RoleAccessControlTest {

    private static final byte[] MESSAGE = "role-check".getBytes(StandardCharsets.UTF_8);

    private HsmToken readyToken(Path dir) {
        HsmToken token = new HsmToken(dir);
        token.initializeToken("so-pin", "user-pin", "roles");
        return token;
    }

    private long session(HsmToken token, UserType role, String pin) {
        long handle = token.openSession();
        token.login(handle, role, pin);
        return handle;
    }

    @Test
    void soSessionIsRejectedFromEveryObjectAndCryptoOperation(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long user = session(token, UserType.USER, "user-pin");
        String aesId = token.generateKey(user, KeyType.AES, 128, "aes",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.WRAP, KeyUsage.UNWRAP), true);
        String rsaId = token.generateKey(user, KeyType.RSA, 2048, "rsa",
                EnumSet.of(KeyUsage.SIGN, KeyUsage.VERIFY));
        byte[] ciphertext = token.encrypt(user, aesId, MESSAGE);
        byte[] signature = token.sign(user, rsaId, MESSAGE);
        byte[] wrapped = token.wrapKey(user, aesId, aesId);
        byte[] rawAes = new CryptoEngine().generateAesKey(128);

        long so = session(token, UserType.SO, "so-pin");

        assertRoleRequired(() -> token.generateKey(so, KeyType.AES, 128, "x",
                EnumSet.of(KeyUsage.ENCRYPT)));
        assertRoleRequired(() -> token.importKey(so, KeyType.AES, "x",
                EnumSet.of(KeyUsage.ENCRYPT), true, rawAes, null));
        assertRoleRequired(() -> token.getKeyInfo(so, aesId));
        assertRoleRequired(() -> token.exportPublicKey(so, rsaId));
        assertRoleRequired(() -> token.destroyKey(so, aesId));
        assertRoleRequired(() -> token.sign(so, rsaId, MESSAGE));
        assertRoleRequired(() -> token.verify(so, rsaId, MESSAGE, signature));
        assertRoleRequired(() -> token.encrypt(so, aesId, MESSAGE));
        assertRoleRequired(() -> token.decrypt(so, aesId, ciphertext));
        assertRoleRequired(() -> token.digest(so, MESSAGE));
        assertRoleRequired(() -> token.wrapKey(so, aesId, aesId));
        assertRoleRequired(() -> token.unwrapKey(so, aesId, wrapped, "x",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.WRAP, KeyUsage.UNWRAP)));

        // The SO rejections did not damage anything: the user session still works.
        assertEquals(MESSAGE.length, token.decrypt(user, aesId, ciphertext).length);
    }

    @Test
    void soRejectionReasonIsDistinctFromOtherSessionFailures(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long so = session(token, UserType.SO, "so-pin");
        HsmException soFailure = assertThrows(HsmException.class,
                () -> token.digest(so, MESSAGE));
        assertEquals(HsmError.ROLE_REQUIRED, soFailure.getError());

        long anonymous = token.openSession();
        HsmException notLoggedIn = assertThrows(HsmException.class,
                () -> token.digest(anonymous, MESSAGE));
        assertEquals(HsmError.NOT_LOGGED_IN, notLoggedIn.getError());

        HsmException badHandle = assertThrows(HsmException.class,
                () -> token.digest(999_999L, MESSAGE));
        assertEquals(HsmError.SESSION_HANDLE_INVALID, badHandle.getError());

        assertNotEquals(soFailure.getError(), notLoggedIn.getError());
        assertNotEquals(soFailure.getError(), badHandle.getError());

        token.lock(so);
        HsmException locked = assertThrows(HsmException.class,
                () -> token.digest(so, MESSAGE));
        assertEquals(HsmError.TOKEN_LOCKED, locked.getError());
        assertNotEquals(soFailure.getError(), locked.getError());
    }

    @Test
    void managementOperationsStayAvailableToSo(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long so = session(token, UserType.SO, "so-pin");

        Map<String, Object> status = token.status();
        assertTrue((Boolean) status.get("initialized"));

        token.lock(so);
        assertTrue(token.isLocked());

        // While locked, even management queries keep working and unlock recovers.
        assertTrue((Boolean) token.status().get("locked"));
        token.unlock("so-pin");
        assertFalse(token.isLocked());

        long user = session(token, UserType.USER, "user-pin");
        String keyId = token.generateKey(user, KeyType.AES, 128, "k",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT));
        assertEquals("AES", token.getKeyInfo(user, keyId).get("keyType"));
    }

    @Test
    void lockedTokenRejectsUserOperationsButNotUnlockOrStatus(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long user = session(token, UserType.USER, "user-pin");
        String keyId = token.generateKey(user, KeyType.AES, 128, "k",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT));
        long so = session(token, UserType.SO, "so-pin");
        token.lock(so);

        HsmException userOp = assertThrows(HsmException.class,
                () -> token.encrypt(user, keyId, MESSAGE));
        assertEquals(HsmError.TOKEN_LOCKED, userOp.getError());
        HsmException soOp = assertThrows(HsmException.class,
                () -> token.digest(so, MESSAGE));
        assertEquals(HsmError.TOKEN_LOCKED, soOp.getError());
        assertThrows(HsmException.class, token::openSession);

        assertTrue((Boolean) token.status().get("locked"));
        token.unlock("so-pin");
        long fresh = session(token, UserType.USER, "user-pin");
        assertEquals("AES", token.getKeyInfo(fresh, keyId).get("keyType"));
    }

    private void assertRoleRequired(Runnable operation) {
        HsmException ex = assertThrows(HsmException.class, operation::run);
        assertEquals(HsmError.ROLE_REQUIRED, ex.getError());
    }
}
