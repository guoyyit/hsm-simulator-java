package com.github.guoyyit.hsmsimulatorjava.hsm.session;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Tracks open sessions for one token. Sessions are process-local and are
 * never persisted: login state is independent per session.
 */
public class SessionManager {

    private final Map<Long, Session> sessions = new ConcurrentHashMap<>();
    private final AtomicLong nextHandle = new AtomicLong(1);

    public Session openSession() {
        long handle = nextHandle.getAndIncrement();
        Session session = new Session(handle);
        sessions.put(handle, session);
        return session;
    }

    public Session get(long handle) {
        return sessions.get(handle);
    }

    public void close(long handle) {
        Session session = sessions.remove(handle);
        if (session != null) {
            session.close();
        }
    }

    /**
     * Closes every open session and returns how many were closed. Handles
     * issued before this call become invalid; the handle counter keeps
     * moving forward so stale handles are never reused.
     */
    public int closeAll() {
        int count = sessions.size();
        sessions.values().forEach(Session::close);
        sessions.clear();
        return count;
    }

    public Collection<Session> all() {
        return Collections.unmodifiableCollection(new ArrayList<>(sessions.values()));
    }
}
