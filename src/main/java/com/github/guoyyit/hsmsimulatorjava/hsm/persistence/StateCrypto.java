package com.github.guoyyit.hsmsimulatorjava.hsm.persistence;

import java.nio.file.Path;

public class StateCrypto {

    private static final int KEY_LENGTH = 32;
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 128;

    private final Path masterKeyFile;
    private final javax.crypto.SecretKey masterKey;

    public StateCrypto(Path masterKeyFile) {
        this.masterKeyFile = masterKeyFile;
        this.masterKey = loadOrCreateMasterKey();
    }

    public byte[] encrypt(byte[] plaintext) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            new java.security.SecureRandom().nextBytes(iv);
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, masterKey,
                    new javax.crypto.spec.GCMParameterSpec(TAG_LENGTH, iv));
            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
            return combined;
        } catch (Exception e) {
            throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                    com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.STORAGE_ERROR,
                    "State encryption failed", e);
        }
    }

    public byte[] decrypt(byte[] ciphertext) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            byte[] body = new byte[ciphertext.length - IV_LENGTH];
            System.arraycopy(ciphertext, 0, iv, 0, IV_LENGTH);
            System.arraycopy(ciphertext, IV_LENGTH, body, 0, body.length);
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, masterKey,
                    new javax.crypto.spec.GCMParameterSpec(TAG_LENGTH, iv));
            return cipher.doFinal(body);
        } catch (Exception e) {
            throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                    com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.STORAGE_ERROR,
                    "State decryption failed", e);
        }
    }

    private javax.crypto.SecretKey loadOrCreateMasterKey() {
        try {
            if (java.nio.file.Files.exists(masterKeyFile)) {
                byte[] raw = java.nio.file.Files.readAllBytes(masterKeyFile);
                if (raw.length != KEY_LENGTH) {
                    throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                            com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.STORAGE_ERROR,
                            "Corrupt master key file");
                }
                return new javax.crypto.spec.SecretKeySpec(raw, "AES");
            }
            java.security.SecureRandom random = new java.security.SecureRandom();
            byte[] raw = new byte[KEY_LENGTH];
            random.nextBytes(raw);
            Path parent = masterKeyFile.getParent();
            if (parent != null) {
                java.nio.file.Files.createDirectories(parent);
            }
            Path temp = masterKeyFile.resolveSibling(masterKeyFile.getFileName() + ".tmp");
            try (java.io.OutputStream out = java.nio.file.Files.newOutputStream(temp)) {
                out.write(raw);
                out.flush();
                if (out instanceof java.io.FileOutputStream fileOut) {
                    fileOut.getFD().sync();
                }
            }
            java.nio.file.Files.move(temp, masterKeyFile,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            try {
                java.nio.file.Files.setAttribute(masterKeyFile, "posix:permissions",
                        java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException ignored) {
                // Non-POSIX file systems keep default permissions.
            }
            return new javax.crypto.spec.SecretKeySpec(raw, "AES");
        } catch (com.github.guoyyit.hsmsimulatorjava.hsm.HsmException e) {
            throw e;
        } catch (Exception e) {
            throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                    com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.STORAGE_ERROR,
                    "Unable to initialize master key", e);
        }
    }
}
