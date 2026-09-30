package com.github.guoyyit.hsmsimulatorjava.hsm;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CrashRecoveryTest {

    @TempDir
    Path tempDir;

    @Test
    void committedStateSurvivesRestart() {
        HsmService initial = new HsmService(tempDir);
        initial.initToken("so-pin", "user-pin");
        String session = initial.openSession();
        initial.login(session, Role.USER, "user-pin");

        KeyObject aes = initial.generateKey(session, KeyType.AES, "persisted-aes",
                Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.WRAP, KeyUsage.UNWRAP),
                true);
        KeyObject kek = initial.generateKey(session, KeyType.RSA, "recovery-kek",
                Set.of(KeyUsage.WRAP, KeyUsage.UNWRAP),
                true);

        byte[] plaintext = "durable".getBytes();
        byte[] ciphertext = initial.encrypt(session, aes.getId(), plaintext);
        WrappedKey wrapped = initial.wrapKey(session, kek.getId(), aes.getId());

        initial.destroyKey(session, aes.getId());

        HsmService restarted = new HsmService(tempDir);
        assertEquals(1, restarted.getTokenStatus().keyCount());

        String newSession = restarted.openSession();
        restarted.login(newSession, Role.USER, "user-pin");

        assertThrows(HsmException.class,
                () -> restarted.decrypt(newSession, aes.getId(), ciphertext));

        KeyObject restored = restarted.unwrapKey(newSession, kek.getId(), wrapped);
        assertArrayEquals(plaintext,
                restarted.decrypt(newSession, restored.getId(), ciphertext));

        HsmService secondRestart = new HsmService(tempDir);
        String thirdSession = secondRestart.openSession();
        secondRestart.login(thirdSession, Role.USER, "user-pin");
        byte[] wrappedAgain = secondRestart.encrypt(thirdSession, restored.getId(), plaintext);
        assertArrayEquals(plaintext,
                secondRestart.decrypt(thirdSession, restored.getId(), wrappedAgain));
    }

    @Test
    void lockedTokenAndPinsSurviveRestart() {
        HsmService initial = new HsmService(tempDir);
        initial.initToken("so-pin", "user-pin");
        String soSession = initial.openSession();
        initial.login(soSession, Role.SO, "so-pin");
        initial.lockToken(soSession);

        HsmService restarted = new HsmService(tempDir);
        assertThrows(HsmException.class, restarted::openSession);

        restarted.unlockToken("so-pin");
        String session = restarted.openSession();
        restarted.login(session, Role.USER, "user-pin");
    }

}
