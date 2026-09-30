package com.github.guoyyit.hsmsimulatorjava.hsm.persistence;

import com.github.guoyyit.hsmsimulatorjava.hsm.TokenState;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.io.FileOutputStream;
import java.io.OutputStream;

public class FileStateStore implements StateStore {

    private static final String STATE_FILE_NAME = "token.state";
    private static final String MASTER_KEY_FILE_NAME = "master.key";

    private final Path stateFile;
    private final StateCrypto stateCrypto;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public FileStateStore(Path dataDir) {
        try {
            Files.createDirectories(dataDir);
        } catch (Exception e) {
            throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                    com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.STORAGE_ERROR,
                    "Cannot create data directory: " + dataDir, e);
        }
        this.stateFile = dataDir.resolve(STATE_FILE_NAME);
        this.stateCrypto = new StateCrypto(dataDir.resolve(MASTER_KEY_FILE_NAME));
    }

    @Override
    public TokenState load() {
        try {
            if (!Files.exists(stateFile)) {
                return new TokenState();
            }
            byte[] encrypted = Files.readAllBytes(stateFile);
            byte[] plaintext = stateCrypto.decrypt(encrypted);
            return objectMapper.readValue(plaintext, TokenState.class);
        } catch (com.github.guoyyit.hsmsimulatorjava.hsm.HsmException e) {
            throw e;
        } catch (Exception e) {
            throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                    com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.STORAGE_ERROR,
                    "Unable to load token state", e);
        }
    }

    @Override
    public void save(TokenState state) {
        try {
            byte[] plaintext = objectMapper.writeValueAsBytes(state);
            byte[] encrypted = stateCrypto.encrypt(plaintext);
            Path temp = stateFile.resolveSibling(STATE_FILE_NAME + ".tmp");
            try (OutputStream out = Files.newOutputStream(temp)) {
                out.write(encrypted);
                out.flush();
                if (out instanceof FileOutputStream fileOut) {
                    fileOut.getFD().sync();
                }
            }
            Files.move(temp, stateFile,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (com.github.guoyyit.hsmsimulatorjava.hsm.HsmException e) {
            throw e;
        } catch (Exception e) {
            throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                    com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.STORAGE_ERROR,
                    "Unable to save token state", e);
        }
    }
}
