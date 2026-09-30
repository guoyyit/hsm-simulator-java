package com.github.guoyyit.hsmsimulatorjava.hsm.session;

import com.github.guoyyit.hsmsimulatorjava.hsm.exception.HsmException;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.HsmError;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.UserType;

/**
 * An open session with a token. Login state is per-session and in-memory.
 */
public class Session {

    private final long handle;
    private volatile UserType role;
    private volatile boolean open = true;
    private final long openedAt;

    public Session(long handle) {
        this.handle = handle;
        this.openedAt = System.currentTimeMillis();
    }

    public long getHandle() {
        return handle;
    }

    public long getOpenedAt() {
        return openedAt;
    }

    public boolean isOpen() {
        return open;
    }

    public void close() {
        this.open = false;
        this.role = null;
    }

    public void login(UserType userType) {
        this.role = userType;
    }

    public void logout() {
        this.role = null;
    }

    public UserType getRole() {
        return role;
    }

    public void requireRole(UserType expected) {
        if (role != expected) {
            throw new HsmException(HsmError.ROLE_REQUIRED,
                    expected + " role required, current=" + role);
        }
    }

    public boolean isLoggedIn() {
        return open && role != null;
    }
}
