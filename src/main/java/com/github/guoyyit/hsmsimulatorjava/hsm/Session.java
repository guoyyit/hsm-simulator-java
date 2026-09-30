package com.github.guoyyit.hsmsimulatorjava.hsm;

public class Session {

    private final String id;
    private volatile Role role;
    private volatile boolean open = true;

    public Session(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public boolean isOpen() {
        return open;
    }

    public void setOpen(boolean open) {
        this.open = open;
    }
}
