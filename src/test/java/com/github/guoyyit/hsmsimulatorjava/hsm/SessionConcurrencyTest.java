package com.github.guoyyit.hsmsimulatorjava.hsm;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionConcurrencyTest {

    @TempDir
    Path tempDir;

    @Test
    void sessionsHaveIndependentLoginState() {
        new HsmService(tempDir).initToken("so-pin", "user-pin");
        HsmService service = new HsmService(tempDir);

        String userSession = service.openSession();
        String soSession = service.openSession();
        String anonymousSession = service.openSession();

        service.login(userSession, Role.USER, "user-pin");
        service.login(soSession, Role.SO, "so-pin");

        KeyObject key = service.generateKey(userSession, KeyType.AES, "shared",
                Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), true);

        byte[] ciphertext = service.encrypt(userSession, key.getId(), "hello".getBytes());
        assertEquals("hello",
                new String(service.decrypt(userSession, key.getId(), ciphertext)));

        assertThrows(HsmException.class,
                () -> service.encrypt(anonymousSession, key.getId(), "hello".getBytes()));
        assertThrows(HsmException.class,
                () -> service.sign(soSession, key.getId(), "x".getBytes()));

        service.closeSession(userSession);

        assertThrows(HsmException.class,
                () -> service.listKeys(soSession));
        assertThrows(HsmException.class,
                () -> service.closeSession(userSession));
        assertEquals(2, service.getTokenStatus().sessionCount());
    }

    @Test
    void closingOneSessionDoesNotAffectOthers() {
        new HsmService(tempDir).initToken("so-pin", "user-pin");
        HsmService service = new HsmService(tempDir);

        List<String> sessions = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            String sessionId = service.openSession();
            service.login(sessionId, Role.USER, "user-pin");
            sessions.add(sessionId);
        }

        service.closeSession(sessions.get(0));
        service.closeSession(sessions.get(2));

        KeyObject key = service.generateKey(sessions.get(1), KeyType.AES, "k",
                Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), true);
        byte[] ciphertext = service.encrypt(sessions.get(3), key.getId(),
                "still-working".getBytes());
        assertEquals("still-working",
                new String(service.decrypt(sessions.get(1), key.getId(), ciphertext)));

        assertThrows(HsmException.class, () -> service.closeSession(sessions.get(0)));
        assertEquals(2, service.getTokenStatus().sessionCount());
    }

    @Test
    void parallelOperationsAcrossSessionsAreConsistent() throws Exception {
        new HsmService(tempDir).initToken("so-pin", "user-pin");
        HsmService service = new HsmService(tempDir);

        String setupSession = service.openSession();
        service.login(setupSession, Role.USER, "user-pin");
        KeyObject rsaKey = service.generateKey(setupSession, KeyType.RSA, "rsa",
                Set.of(KeyUsage.SIGN, KeyUsage.VERIFY), true);
        String rsaKeyId = rsaKey.getId();

        int threads = 8;
        int iterations = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Callable<Boolean>> tasks = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            tasks.add(() -> {
                String sessionId = service.openSession();
                service.login(sessionId, Role.USER, "user-pin");
                start.await(60, TimeUnit.SECONDS);
                for (int i = 0; i < iterations; i++) {
                    byte[] data = ("payload-" + i).getBytes();
                    byte[] signature = service.sign(sessionId, rsaKeyId, data);
                    if (!service.verify(sessionId, rsaKeyId, data, signature)) {
                        return false;
                    }
                }
                return true;
            });
        }
        start.countDown();
        List<Future<Boolean>> futures = pool.invokeAll(tasks);
        for (Future<Boolean> future : futures) {
            assertTrue(future.get(60, TimeUnit.SECONDS));
        }
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));
    }
}
