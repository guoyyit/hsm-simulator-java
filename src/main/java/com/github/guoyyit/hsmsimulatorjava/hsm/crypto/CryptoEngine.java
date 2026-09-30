package com.github.guoyyit.hsmsimulatorjava.hsm.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Stateless JCA-backed cryptographic primitives used by the token.
 */
public class CryptoEngine {

    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_BITS = 128;
    private static final int PIN_ITERATIONS = 200_000;
    private static final int PIN_HASH_BITS = 256;

    private final SecureRandom secureRandom = new SecureRandom();

    public byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    public byte[] generateAesKey(int bits) {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(bits, secureRandom);
            return generator.generateKey().getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES key generation failed", e);
        }
    }

    public Map<String, byte[]> generateRsaKeyPair(int bits) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(bits, secureRandom);
            KeyPair keyPair = generator.generateKeyPair();
            Map<String, byte[]> pair = new LinkedHashMap<>();
            pair.put("private", keyPair.getPrivate().getEncoded());
            pair.put("public", keyPair.getPublic().getEncoded());
            return pair;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("RSA key generation failed", e);
        }
    }

    public byte[] hashPin(char[] pin, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(pin, salt, PIN_ITERATIONS, PIN_HASH_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PIN hashing failed", e);
        }
    }

    public byte[] newSalt() {
        return randomBytes(16);
    }

    public byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public byte[] signRsaSha256(byte[] derPrivateKey, byte[] data) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(loadRsaPrivateKey(derPrivateKey));
            signature.update(data);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("RSA signing failed", e);
        }
    }

    public boolean verifyRsaSha256(byte[] x509PublicKey, byte[] data, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(loadRsaPublicKey(x509PublicKey));
            verifier.update(data);
            return verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public byte[] rsaEncrypt(byte[] x509PublicKey, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, loadRsaPublicKey(x509PublicKey));
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("RSA encryption failed", e);
        }
    }

    public byte[] rsaDecrypt(byte[] derPrivateKey, byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, loadRsaPrivateKey(derPrivateKey));
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

    public byte[] aesGcmEncrypt(byte[] rawKey, byte[] plaintext, byte[] iv, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rawKey, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM encryption failed", e);
        }
    }

    public byte[] aesGcmDecrypt(byte[] rawKey, byte[] ciphertext, byte[] iv, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rawKey, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

    public byte[] aesGcmEncryptWithIv(byte[] rawKey, byte[] plaintext, byte[] aad) {
        byte[] iv = randomBytes(GCM_IV_LENGTH);
        byte[] ciphertext = aesGcmEncrypt(rawKey, plaintext, iv, aad);
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        return combined;
    }

    public byte[] aesGcmDecryptWithIv(byte[] rawKey, byte[] combined, byte[] aad) {
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] ciphertext = new byte[combined.length - GCM_IV_LENGTH];
        System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH);
        System.arraycopy(combined, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);
        return aesGcmDecrypt(rawKey, ciphertext, iv, aad);
    }

    private PrivateKey loadRsaPrivateKey(byte[] der) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private PublicKey loadRsaPublicKey(byte[] x509) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(x509));
    }
}
