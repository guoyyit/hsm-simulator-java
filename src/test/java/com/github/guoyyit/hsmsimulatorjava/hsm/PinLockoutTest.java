package com.github.guoyyit.hsmsimulatorjava.hsm;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PinLockoutTest {

    @TempDir
    Path tempDir;

    @Test
    void userLocksAfterMaxFailedAttemptsAndRemainsLockedAfterRestart() {
        new HsmService(tempDir).initToken("so-pin", "user-pin");

        HsmService service = new HsmService(tempDir);
        String session = service.openSession();

        HsmException first = assertThrows(HsmException.class,
                () -> service.login(session, Role.USER, "wrong"));
        assertEquals(HsmErrorCode.INVALID_PIN, first.getCode());
        HsmException second = assertThrows(HsmException.class,
                () -> service.login(openFreshSession(service), Role.USER, "wrong"));
        assertEquals(HsmErrorCode.INVALID_PIN, second.getCode());
        HsmException third = assertThrows(HsmException.class,
                () -> service.login(openFreshSession(service), Role.USER, "wrong"));
        assertEquals(HsmErrorCode.PIN_LOCKED, third.getCode());

        HsmException afterLock = assertThrows(HsmException.class,
                () -> service.login(openFreshSession(service), Role.USER, "user-pin"));
        assertEquals(HsmErrorCode.PIN_LOCKED, afterLock.getCode());

        TokenStatus status = service.getTokenStatus();
        assertTrue(status.userLocked());
        assertEquals(3, status.userFailures());

        HsmService restarted = new HsmService(tempDir);
        assertTrue(restarted.getTokenStatus().userLocked());
        String postRestartSession = restarted.openSession();
        assertThrows(HsmException.class,
                () -> restarted.login(postRestartSession, Role.USER, "user-pin"));
    }

    @Test
    void soUnlockResetsUserFailuresAndLock() {
        new HsmService(tempDir).initToken("so-pin", "user-pin");
        HsmService service = new HsmService(tempDir);

        assertThrows(HsmException.class,
                () -> service.login(service.openSession(), Role.USER, "bad"));
        assertThrows(HsmException.class,
                () -> service.login(service.openSession(), Role.USER, "bad"));

        service.unlockToken("so-pin");

        TokenStatus status = service.getTokenStatus();
        assertFalse(status.userLocked());
        assertEquals(0, status.userFailures());
        assertFalse(status.locked());

        service.login(service.openSession(), Role.USER, "user-pin");
    }

    @Test
    void correctPinResetsFailureCount() {
        new HsmService(tempDir).initToken("so-pin", "user-pin");
        HsmService service = new HsmService(tempDir);

        assertThrows(HsmException.class,
                () -> service.login(service.openSession(), Role.USER, "bad"));
        service.login(service.openSession(), Role.USER, "user-pin");

        assertEquals(0, service.getTokenStatus().userFailures());
    }

    private static String openFreshSession(HsmService service) {
        return service.openSession();
    }
}
