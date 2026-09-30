package com.github.guoyyit.hsmsimulatorjava.hsm;

import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class SessionManager {

    private final ConcurrentHashMap<String, Session> sessions = new ConcurrentHashMap<>();

    public Session openSession() {
        String sessionId = UUID.randomUUID().toString();
        Session session = new Session(sessionId);
        sessions.put(sessionId, session);
        return session;
    }

    public Session getSession(String sessionId) {
        if (sessionId == null) {
            return null;
        }
        Session session = sessions.get(sessionId);
        if (session == null || !session.isOpen()) {
            return null;
        }
        return session;
    }

    public boolean closeSession(String sessionId) {
        Session session = sessions.remove(sessionId);
        if (session == null) {
            return false;
        }
        session.setOpen(false);
        return true;
    }

    public void closeAllSessions() {
        sessions.values().forEach(session -> session.setOpen(false));
        sessions.clear();
    }

    public int sessionCount() {
        return sessions.size();
    }

    public Collection<Session> allSessions() {
        return Collections.unmodifiableCollection(sessions.values());
    }
}
