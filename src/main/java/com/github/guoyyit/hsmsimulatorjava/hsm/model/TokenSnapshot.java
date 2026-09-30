package com.github.guoyyit.hsmsimulatorjava.hsm.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Full durable state of a token, serialized atomically on every mutation.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenSnapshot {

    public static final int CURRENT_VERSION = 1;

    private int version;
    private boolean initialized;
    private boolean locked;
    private String label;
    private Map<UserType, PinRecord> pins = new LinkedHashMap<>();
    private Map<String, StoredKey> keys = new LinkedHashMap<>();

    public TokenSnapshot() {
    }

    public static TokenSnapshot uninitialized() {
        TokenSnapshot snapshot = new TokenSnapshot();
        snapshot.version = CURRENT_VERSION;
        return snapshot;
    }

    public PinRecord pinRecord(UserType userType) {
        return pins.computeIfAbsent(userType, ignored -> new PinRecord());
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public boolean isInitialized() {
        return initialized;
    }

    public void setInitialized(boolean initialized) {
        this.initialized = initialized;
    }

    public boolean isLocked() {
        return locked;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public Map<UserType, PinRecord> getPins() {
        return pins;
    }

    public void setPins(Map<UserType, PinRecord> pins) {
        this.pins = pins;
    }

    public Map<String, StoredKey> getKeys() {
        return keys;
    }

    public void setKeys(Map<String, StoredKey> keys) {
        this.keys = keys;
    }

    /**
     * Durable per-role authentication record. Failures accumulate per user
     * type and survive restarts; {@code locked} is PIN-lockout, distinct from
     * the token-wide lock.
     */
    public static class PinRecord {
        private byte[] salt;
        private byte[] hash;
        private int failCount;
        private boolean locked;

        public PinRecord() {
        }

        public byte[] getSalt() {
            return salt;
        }

        public void setSalt(byte[] salt) {
            this.salt = salt;
        }

        public byte[] getHash() {
            return hash;
        }

        public void setHash(byte[] hash) {
            this.hash = hash;
        }

        public int getFailCount() {
            return failCount;
        }

        public void setFailCount(int failCount) {
            this.failCount = failCount;
        }

        public boolean isLocked() {
            return locked;
        }

        public void setLocked(boolean locked) {
            this.locked = locked;
        }
    }
}
