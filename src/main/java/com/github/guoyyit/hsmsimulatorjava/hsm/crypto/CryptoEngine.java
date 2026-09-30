package com.github.guoyyit.hsmsimulatorjava.hsm.crypto;

import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Component
public class CryptoEngine {

    private static final int RSA_KEY_SIZE = 2048;
    private static final int AES_KEY_SIZE = 128;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final String RSA_SIGN_ALG = "SHA256withRSA";
    private static final String RSA_CIPHER = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String AES_GCM = "AES/GCM/NoPadding";

    public KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(RSA_KEY_SIZE);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                    com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.CRYPTO_FAILED,
                    "RSA key generation failed", e);
        }
    }

    public SecretKey generateAesKey() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(AES_KEY_SIZE);
            return generator.generateKey();
        } catch (Exception e) {
            throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                    com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.CRYPTO_FAILED,
                    "AES key generation failed", e);
        }
    }

    public byte[] signRsa(PrivateKey privateKey, byte[] data) {
        try {
            Signature signature = Signature.getInstance(RSA_SIGN_ALG);
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                    com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.CRYPTO_FAILED,
                    "RSA signing failed", e);
        }
    }

    public boolean verifyRsa(PublicKey publicKey, byte[] data, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance(RSA_SIGN_ALG);
            verifier.initVerify(publicKey);
            verifier.update(data);
            return verifier.verify(signature);
        } catch (Exception e) {
            throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                    com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.CRYPTO_FAILED,
                    "RSA verification failed", e);
        }
    }

    public byte[] rsaEncrypt(PublicKey publicKey, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                    com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.CRYPTO_FAILED,
                    "RSA encryption failed", e);
        }
    }

    public byte[] rsaDecrypt(PrivateKey privateKey, byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                    com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.CRYPTO_FAILED,
                    "RSA decryption failed", e);
        }
    }

    public byte[] aesGcmEncrypt(SecretKey key, byte[] data, byte[] aad) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            new java.security.SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            byte[] ciphertext = cipher.doFinal(data);
            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
            return combined;
        } catch (Exception e) {
            throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                    com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.CRYPTO_FAILED,
                    "AES-GCM encryption failed", e);
        }
    }

    public byte[] aesGcmDecrypt(SecretKey key, byte[] ivCiphertext, byte[] aad) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            byte[] ciphertext = new byte[ivCiphertext.length - GCM_IV_LENGTH];
            System.arraycopy(ivCiphertext, 0, iv, 0, GCM_IV_LENGTH);
            System.arraycopy(ivCiphertext, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                    com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.CRYPTO_FAILED,
                    "AES-GCM decryption failed", e);
        }
    }

    public byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                    com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.CRYPTO_FAILED,
                    "SHA-256 digest failed", e);
        }
    }

    public SecretKey aesKeyFromBytes(byte[] raw) {
        return new SecretKeySpec(raw, "AES");
    }

    public PrivateKey rsaPrivateFromPkcs8(byte[] encoded) {
        try {
            return KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                    com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.INVALID_ARGUMENT,
                    "Invalid PKCS#8 RSA private key", e);
        }
    }

    public PublicKey rsaPublicFromX509(byte[] encoded) {
        try {
            return KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new com.github.guoyyit.hsmsimulatorjava.hsm.HsmException(
                    com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode.INVALID_ARGUMENT,
                    "Invalid X.509 RSA public key", e);
        }
    }
}
