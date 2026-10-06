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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Key-object management and cryptographic operations are USER-only. SO
 * sessions must be rejected with {@link HsmError#ROLE_REQUIRED}, a reason
 * distinguishable from not-logged-in, invalid-handle and token-locked.
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
    void soSessionIsRejectedFromEveryKeyAndCryptoOperation(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long user = session(token, UserType.USER, "user-pin");
        String aesId = token.generateKey(user, KeyType.AES, 128, "aes",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.WRAP, KeyUsage.UNWRAP), true);
        String rsaId = token.generateKey(user, KeyType.RSA, 2048, "rsa",
                EnumSet.of(KeyUsage.SIGN, KeyUsage.VERIFY));
        byte[] signature = token.sign(user, rsaId, MESSAGE);
        byte[] ciphertext = token.encrypt(user, aesId, MESSAGE);
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
        assertRoleRequired(() -> token.unwrapKey(so, aesId, wrapped, "x", null));

        // The rejection reason is none of the other authentication failures.
        HsmException ex = assertThrows(HsmException.class, () -> token.getKeyInfo(so, aesId));
        assertNotEquals(HsmError.NOT_LOGGED_IN, ex.getError());
        assertNotEquals(HsmError.SESSION_HANDLE_INVALID, ex.getError());
        assertNotEquals(HsmError.TOKEN_LOCKED, ex.getError());

        // The SO session itself stays usable for management actions.
        token.lock(so);
        assertTrue(token.isLocked());
        token.unlock("so-pin");
    }

    @Test
    void userSessionKeepsFullAccess(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long user = session(token, UserType.USER, "user-pin");
        String keyId = token.generateKey(user, KeyType.AES, 128, "k",
                EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT));
        byte[] ciphertext = token.encrypt(user, keyId, MESSAGE);
        token.decrypt(user, keyId, ciphertext);
        token.digest(user, MESSAGE);
        token.getKeyInfo(user, keyId);
        token.destroyKey(user, keyId);
    }

    @Test
    void roleRejectionSurvivesRestart(@TempDir Path dir) {
        HsmToken before = readyToken(dir);
        long user = session(before, UserType.USER, "user-pin");
        String keyId = before.generateKey(user, KeyType.AES, 128, "k",
                EnumSet.of(KeyUsage.ENCRYPT));

        HsmToken after = new HsmToken(dir);
        long so = session(after, UserType.SO, "so-pin");
        assertRoleRequired(() -> after.getKeyInfo(so, keyId));
        long restartedUser = session(after, UserType.USER, "user-pin");
        assertEquals("k", after.getKeyInfo(restartedUser, keyId).get("label"));
    }

    @Test
    void lockedTokenStillRejectsSoKeyOperationsAsTokenLocked(@TempDir Path dir) {
        HsmToken token = readyToken(dir);
        long so = session(token, UserType.SO, "so-pin");
        token.lock(so);
        // While locked the token-level reason takes precedence and stays
        // distinguishable from the role reason.
        HsmException ex = assertThrows(HsmException.class,
                () -> token.digest(so, MESSAGE));
        assertEquals(HsmError.TOKEN_LOCKED, ex.getError());
        token.unlock("so-pin");
        // unlock closes all sessions; a fresh SO session is still rejected
        // from user operations with the role reason.
        long soAfter = session(token, UserType.SO, "so-pin");
        assertRoleRequired(() -> token.digest(soAfter, MESSAGE));
    }

    private void assertRoleRequired(ThrowingCall call) {
        HsmException ex = assertThrows(HsmException.class, call::run);
        assertEquals(HsmError.ROLE_REQUIRED, ex.getError());
    }

    @FunctionalInterface
    private interface ThrowingCall {
        void run();
    }
}
