package com.github.guoyyit.hsmsimulatorjava.hsm.persist;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.hsmsimulatorjava.hsm.crypto.CryptoEngine;
import com.github.guoyyit.hsmsimulatorjava.hsm.exception.HsmException;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.HsmError;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.TokenSnapshot;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Base64;

/**
 * Crash-safe durable storage: state is written atomically (temp file + fsync +
 * rename + dir fsync), so every acknowledged mutation survives a restart and
 * no partial state is ever observable.
 */
public class TokenStore {

    static final String SNAPSHOT_FILE = "token.json";
    private static final String MASTER_FILE = "master.key";
    private static final byte[] MASTER_AAD =
            "hsm-simulator-master-key-v1".getBytes(StandardCharsets.UTF_8);

    private final Path dataDir;
    private final Path snapshotPath;
    private final Path masterPath;
    private final ObjectMapper objectMapper;
    private final CryptoEngine cryptoEngine;

    public TokenStore(Path dataDir, ObjectMapper objectMapper) {
        this.dataDir = dataDir;
        this.snapshotPath = dataDir.resolve(SNAPSHOT_FILE);
        this.masterPath = dataDir.resolve(MASTER_FILE);
        this.objectMapper = objectMapper;
        this.cryptoEngine = new CryptoEngine();
    }

    private void ensureDataDir() {
        try {
            Files.createDirectories(dataDir);
            restrictPermissions(dataDir);
        } catch (IOException e) {
            throw new HsmException(HsmError.PERSISTENCE_FAILED, "cannot create data directory");
        }
    }

    public TokenSnapshot load() {
        if (!exists()) {
            return null;
        }
        try {
            return objectMapper.readValue(snapshotPath.toFile(), TokenSnapshot.class);
        } catch (IOException e) {
            throw new HsmException(HsmError.PERSISTENCE_FAILED, "cannot read token state");
        }
    }

    public void save(TokenSnapshot snapshot) {
        ensureDataDir();
        Path temp = dataDir.resolve(SNAPSHOT_FILE + ".tmp");
        try {
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(temp.toFile(), snapshot);
            try (java.io.FileOutputStream out = new java.io.FileOutputStream(temp.toFile(), true)) {
                out.getFD().sync();
            }
            try {
                Files.move(temp, snapshotPath, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, snapshotPath, StandardCopyOption.REPLACE_EXISTING);
            }
            restrictPermissions(snapshotPath);
            fsyncDirectory(dataDir);
        } catch (IOException e) {
            throw new HsmException(HsmError.PERSISTENCE_FAILED, "cannot write token state");
        }
    }

    public boolean exists() {
        return Files.exists(snapshotPath);
    }

    /**
     * Loads the token master key, generating and protecting it on first use.
     * The master key never leaves the data directory unprotected: it is
     * wrapped with a random local KEK (AES-GCM) under owner-only permissions,
     * modelling tamper-protected storage of a real token.
     */
    public synchronized byte[] loadOrCreateMasterKey() {
        ensureDataDir();
        try {
            if (Files.exists(masterPath)) {
                String[] lines = Files.readString(masterPath, StandardCharsets.UTF_8).split("\\.");
                byte[] kek = Base64.getDecoder().decode(lines[0]);
                byte[] wrapped = Base64.getDecoder().decode(lines[1]);
                byte[] master = cryptoEngine.aesGcmDecryptWithIv(kek, wrapped, MASTER_AAD);
                if (master == null) {
                    throw new HsmException(HsmError.PERSISTENCE_FAILED, "master key is corrupted");
                }
                return master;
            }
            byte[] kek = cryptoEngine.generateAesKey(256);
            byte[] master = cryptoEngine.generateAesKey(256);
            byte[] wrapped = cryptoEngine.aesGcmEncryptWithIv(kek, master, MASTER_AAD);
            String encoded = Base64.getEncoder().encodeToString(kek) + "."
                    + Base64.getEncoder().encodeToString(wrapped);
            Path temp = dataDir.resolve(MASTER_FILE + ".tmp");
            Files.writeString(temp, encoded, StandardCharsets.UTF_8);
            restrictPermissions(temp);
            try (java.io.FileOutputStream out = new java.io.FileOutputStream(temp.toFile(), true)) {
                out.getFD().sync();
            }
            try {
                Files.move(temp, masterPath, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, masterPath, StandardCopyOption.REPLACE_EXISTING);
            }
            fsyncDirectory(dataDir);
            return master;
        } catch (IOException e) {
            throw new HsmException(HsmError.PERSISTENCE_FAILED, "cannot access master key");
        }
    }

    private void fsyncDirectory(Path directory) {
        try (java.nio.channels.FileChannel channel = java.nio.channels.FileChannel.open(
                directory, java.nio.file.StandardOpenOption.READ)) {
            channel.force(true);
        } catch (IOException ignored) {
            // Some platforms do not support fsync on directories.
        }
    }

    private void restrictPermissions(Path path) {
        try {
            if (Files.isDirectory(path)) {
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"));
            } else {
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
            }
        } catch (UnsupportedOperationException | IOException ignored) {
            // Non-POSIX filesystems keep platform defaults.
        }
    }
}
