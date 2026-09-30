package com.github.guoyyit.hsmsimulatorjava.hsm;

import java.util.LinkedHashMap;
import java.util.Map;

public class TokenState {

    private boolean initialized;
    private boolean locked;
    private String soPinHash;
    private String userPinHash;
    private int soFailures;
    private int userFailures;
    private boolean soLocked;
    private boolean userLocked;
    private int maxAttempts = 3;
    private Map<String, KeyObject> keys = new LinkedHashMap<>();

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

    public String getSoPinHash() {
        return soPinHash;
    }

    public void setSoPinHash(String soPinHash) {
        this.soPinHash = soPinHash;
    }

    public String getUserPinHash() {
        return userPinHash;
    }

    public void setUserPinHash(String userPinHash) {
        this.userPinHash = userPinHash;
    }

    public int getSoFailures() {
        return soFailures;
    }

    public void setSoFailures(int soFailures) {
        this.soFailures = soFailures;
    }

    public int getUserFailures() {
        return userFailures;
    }

    public void setUserFailures(int userFailures) {
        this.userFailures = userFailures;
    }

    public boolean isSoLocked() {
        return soLocked;
    }

    public void setSoLocked(boolean soLocked) {
        this.soLocked = soLocked;
    }

    public boolean isUserLocked() {
        return userLocked;
    }

    public void setUserLocked(boolean userLocked) {
        this.userLocked = userLocked;
    }

    public int getMaxAttempts() {
        return maxAttempts;
    }

    public void setMaxAttempts(int maxAttempts) {
        this.maxAttempts = maxAttempts;
    }

    public Map<String, KeyObject> getKeys() {
        return keys;
    }

    public void setKeys(Map<String, KeyObject> keys) {
        this.keys = keys;
    }
}
