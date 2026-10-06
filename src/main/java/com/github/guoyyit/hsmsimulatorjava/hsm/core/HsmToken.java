package com.github.guoyyit.hsmsimulatorjava.hsm.core;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.hsmsimulatorjava.hsm.crypto.CryptoEngine;
import com.github.guoyyit.hsmsimulatorjava.hsm.exception.HsmException;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.HsmError;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.KeyType;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.KeyUsage;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.StoredKey;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.TokenSnapshot;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.UserType;
import com.github.guoyyit.hsmsimulatorjava.hsm.persist.TokenStore;
import com.github.guoyyit.hsmsimulatorjava.hsm.session.Session;
import com.github.guoyyit.hsmsimulatorjava.hsm.session.SessionManager;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.security.MessageDigest;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Simulated PKCS#11-style HSM token; one token per data directory.
 *
 * <p>Durable mutations run under a single lock and are committed by one
 * atomic full-snapshot write before returning. Sessions are in-memory only,
 * so closing one session never affects another session's login state.</p>
 */
public class HsmToken {

    static final int DEFAULT_MAX_PIN_ATTEMPTS = 3;

    /**
     * AAD for user-data AES-GCM. It must not depend on the key id: an
     * unwrapped copy carries the same material under a new id and has to
     * interoperate with the source key in both directions.
     */
    private static final byte[] DATA_AAD =
            "hsm-data-protection-v1".getBytes(StandardCharsets.UTF_8);

    private final CryptoEngine crypto = new CryptoEngine();
    private final SessionManager sessions = new SessionManager();
    private final Object lock = new Object();
    private final ObjectMapper mapper = new ObjectMapper();
    private final int maxPinAttempts;
    private final byte[] masterKey;
    private final TokenStore store;

    private TokenSnapshot snapshot;

    public HsmToken(Path dataDir) {
        this(dataDir, DEFAULT_MAX_PIN_ATTEMPTS);
    }

    public HsmToken(Path dataDir, int maxPinAttempts) {
        this.store = new TokenStore(dataDir, new ObjectMapper());
        this.maxPinAttempts = maxPinAttempts;
        TokenSnapshot loaded = store.load();
        this.snapshot = loaded != null ? loaded : TokenSnapshot.uninitialized();
        this.masterKey = store.loadOrCreateMasterKey();
    }

    // --------------------------------------------------------------- token

    public void initializeToken(String soPin, String userPin, String label) {
        requirePin(soPin, "soPin");
        requirePin(userPin, "userPin");
        synchronized (lock) {
            if (snapshot.isInitialized()) {
                throw new HsmException(HsmError.TOKEN_ALREADY_INITIALIZED);
            }
            TokenSnapshot fresh = TokenSnapshot.uninitialized();
            fresh.setInitialized(true);
            fresh.setLabel(label != null ? label : "simulated-hsm-token");
            installPin(fresh, UserType.SO, soPin);
            installPin(fresh, UserType.USER, userPin);
            persist(fresh);
        }
    }

    public boolean isInitialized() {
        synchronized (lock) {
            return snapshot.isInitialized();
        }
    }

    public boolean isLocked() {
        synchronized (lock) {
            return snapshot.isLocked();
        }
    }

    public void lock(long sessionHandle) {
        synchronized (lock) {
            requireInitialized();
            requireOpenSession(sessionHandle).requireRole(UserType.SO);
            snapshot.setLocked(true);
            persist(snapshot);
        }
    }

    /**
     * Unlock is a management action allowed while locked. A correct SO PIN
     * clears the ordinary user's failed-attempt counter and PIN lockout, then
     * closes all sessions.
     */
    public void unlock(String soPin) {
        requirePin(soPin, "soPin");
        synchronized (lock) {
            requireInitialized();
            verifyPin(UserType.SO, soPin);
            TokenSnapshot.PinRecord userRecord = snapshot.pinRecord(UserType.USER);
            userRecord.setFailCount(0);
            userRecord.setLocked(false);
            snapshot.setLocked(false);
            sessions.closeAll();
            persist(snapshot);
        }
    }

    // ------------------------------------------------------------ sessions

    public long openSession() {
        synchronized (lock) {
            requireInitialized();
            if (snapshot.isLocked()) {
                throw new HsmException(HsmError.TOKEN_LOCKED);
            }
            return sessions.openSession().getHandle();
        }
    }

    public void closeSession(long handle) {
        sessions.close(handle);
    }

    /**
     * Drops every open session in one serialized step. Only in-memory session
     * state is affected: the lock flag, PIN counters and key objects are
     * untouched, and new sessions can be opened and logged in immediately
     * afterwards. Closing a single session never interferes with this.
     */
    public void closeAllSessions() {
        synchronized (lock) {
            sessions.closeAll();
        }
    }

    public void login(long sessionHandle, UserType userType, String pin) {
        if (userType == null) {
            throw new HsmException(HsmError.INVALID_ARGUMENT, "userType required");
        }
        requirePin(pin, "pin");
        synchronized (lock) {
            requireInitialized();
            if (snapshot.isLocked()) {
                throw new HsmException(HsmError.TOKEN_LOCKED);
            }
            Session session = requireOpenSession(sessionHandle);
            if (session.isLoggedIn()) {
                throw new HsmException(HsmError.ALREADY_LOGGED_IN);
            }
            verifyPin(userType, pin);
            session.login(userType);
        }
    }

    public void logout(long sessionHandle) {
        requireOpenSession(sessionHandle).logout();
    }

    public UserType currentRole(long sessionHandle) {
        return requireOpenSession(sessionHandle).getRole();
    }

    // ---------------------------------------------------------------- keys

    public String generateKey(long sessionHandle, KeyType keyType, int bits,
                              String label, Set<KeyUsage> usages) {
        return generateKey(sessionHandle, keyType, bits, label, usages, null);
    }

    /**
     * Generates a key. {@code extractable} decides whether the key may be
     * exported via wrapping; when {@code null} the existing default
     * (non-extractable) applies. The attribute is persisted with the token
     * state and reported by {@link #getKeyInfo}.
     */
    public String generateKey(long sessionHandle, KeyType keyType, int bits,
                              String label, Set<KeyUsage> usages, Boolean extractable) {
        if (keyType == null) {
            throw new HsmException(HsmError.INVALID_ARGUMENT, "keyType required");
        }
        Set<KeyUsage> normalizedUsages = normalizeUsages(usages);
        synchronized (lock) {
            requireOperableSession(sessionHandle);
            String id = newKeyId();
            byte[] protectedMaterial;
            byte[] publicMaterial = null;
            int keyBits;
            if (keyType == KeyType.AES) {
                int aesBits = bits > 0 ? bits : 256;
                if (aesBits != 128 && aesBits != 192 && aesBits != 256) {
                    throw new HsmException(HsmError.INVALID_ARGUMENT, "AES bits must be 128/192/256");
                }
                protectedMaterial = protect(id, crypto.generateAesKey(aesBits));
                keyBits = aesBits;
            } else {
                int rsaBits = bits > 0 ? bits : 2048;
                if (rsaBits < 2048) {
                    throw new HsmException(HsmError.INVALID_ARGUMENT, "RSA bits must be >= 2048");
                }
                Map<String, byte[]> pair = crypto.generateRsaKeyPair(rsaBits);
                protectedMaterial = protect(id, pair.get("private"));
                publicMaterial = pair.get("public");
                keyBits = rsaBits;
            }
            StoredKey key = new StoredKey(id, safeLabel(label), keyType, keyBits,
                    normalizedUsages, true, resolveExtractable(extractable), System.currentTimeMillis(),
                    protectedMaterial, publicMaterial);
            snapshot.getKeys().put(id, key);
            persist(snapshot);
            return id;
        }
    }

    public String importKey(long sessionHandle, KeyType keyType, String label, Set<KeyUsage> usages,
                            boolean sensitive, byte[] rawOrPrivate, byte[] publicPart) {
        return importKey(sessionHandle, keyType, label, usages, sensitive, rawOrPrivate, publicPart, null);
    }

    /**
     * Imports a key. {@code extractable} decides whether the key may be
     * exported via wrapping; when {@code null} the existing default
     * (non-extractable) applies.
     */
    public String importKey(long sessionHandle, KeyType keyType, String label, Set<KeyUsage> usages,
                            boolean sensitive, byte[] rawOrPrivate, byte[] publicPart,
                            Boolean extractable) {
        if (keyType == null || rawOrPrivate == null || rawOrPrivate.length == 0) {
            throw new HsmException(HsmError.INVALID_ARGUMENT, "keyType and material required");
        }
        Set<KeyUsage> normalizedUsages = normalizeUsages(usages);
        synchronized (lock) {
            requireOperableSession(sessionHandle);
            String id = newKeyId();
            int keyBits;
            byte[] publicMaterial = null;
            if (keyType == KeyType.AES) {
                int aesBits = rawOrPrivate.length * 8;
                if (aesBits != 128 && aesBits != 192 && aesBits != 256) {
                    throw new HsmException(HsmError.INVALID_ARGUMENT, "AES key must be 16/24/32 bytes");
                }
                keyBits = aesBits;
            } else {
                if (publicPart == null || publicPart.length == 0) {
                    throw new HsmException(HsmError.INVALID_ARGUMENT, "RSA public part required");
                }
                publicMaterial = publicPart;
                keyBits = rsaKeyBits(rawOrPrivate);
            }
            StoredKey key = new StoredKey(id, safeLabel(label), keyType, keyBits,
                    normalizedUsages, sensitive, resolveExtractable(extractable), System.currentTimeMillis(),
                    protect(id, rawOrPrivate), publicMaterial);
            snapshot.getKeys().put(id, key);
            persist(snapshot);
            return id;
        }
    }

    public Map<String, Object> getKeyInfo(long sessionHandle, String keyId) {
        synchronized (lock) {
            requireOperableSession(sessionHandle);
            return describe(requireExistingKey(keyId));
        }
    }

    public byte[] exportPublicKey(long sessionHandle, String keyId) {
        synchronized (lock) {
            requireOperableSession(sessionHandle);
            StoredKey key = requireExistingKey(keyId);
            if (key.getKeyType() != KeyType.RSA || key.getPublicMaterial() == null) {
                throw new HsmException(HsmError.INVALID_KEY_TYPE, "key has no public component");
            }
            return key.getPublicMaterial().clone();
        }
    }

    public void destroyKey(long sessionHandle, String keyId) {
        synchronized (lock) {
            requireOperableSession(sessionHandle);
            requireExistingKey(keyId).markDestroyed();
            persist(snapshot);
        }
    }

    // -------------------------------------------------------------- crypto

    public byte[] sign(long sessionHandle, String keyId, byte[] data) {
        requireData(data);
        synchronized (lock) {
            requireOperableSession(sessionHandle);
            StoredKey key = requireUsableKey(keyId, KeyUsage.SIGN);
            if (key.getKeyType() != KeyType.RSA) {
                throw new HsmException(HsmError.INVALID_KEY_TYPE, "only RSA keys can sign");
            }
            return crypto.signRsaSha256(unprotect(key), data);
        }
    }

    public boolean verify(long sessionHandle, String keyId, byte[] data, byte[] signature) {
        requireData(data);
        if (signature == null) {
            throw new HsmException(HsmError.INVALID_ARGUMENT, "signature required");
        }
        synchronized (lock) {
            requireOperableSession(sessionHandle);
            StoredKey key = requireUsableKey(keyId, KeyUsage.VERIFY);
            if (key.getKeyType() != KeyType.RSA) {
                throw new HsmException(HsmError.INVALID_KEY_TYPE, "only RSA keys can verify");
            }
            return crypto.verifyRsaSha256(key.getPublicMaterial(), data, signature);
        }
    }

    public byte[] encrypt(long sessionHandle, String keyId, byte[] data) {
        requireData(data);
        synchronized (lock) {
            requireOperableSession(sessionHandle);
            StoredKey key = requireUsableKey(keyId, KeyUsage.ENCRYPT);
            if (key.getKeyType() == KeyType.AES) {
                return crypto.aesGcmEncryptWithIv(unprotect(key), data, DATA_AAD);
            }
            return crypto.rsaEncrypt(key.getPublicMaterial(), data);
        }
    }

    public byte[] decrypt(long sessionHandle, String keyId, byte[] ciphertext) {
        requireData(ciphertext);
        synchronized (lock) {
            requireOperableSession(sessionHandle);
            StoredKey key = requireUsableKey(keyId, KeyUsage.DECRYPT);
            byte[] plaintext = key.getKeyType() == KeyType.AES
                    ? crypto.aesGcmDecryptWithIv(unprotect(key), ciphertext, DATA_AAD)
                    : crypto.rsaDecrypt(unprotect(key), ciphertext);
            if (plaintext == null) {
                throw new HsmException(HsmError.DECRYPT_FAILED);
            }
            return plaintext;
        }
    }

    public byte[] digest(long sessionHandle, byte[] data) {
        requireData(data);
        synchronized (lock) {
            requireOperableSession(sessionHandle);
            return crypto.sha256(data);
        }
    }

    // ------------------------------------------------------- wrap/unwrap

    /**
     * Exports a key only as protected ciphertext under an AES wrapping key
     * that permits WRAP. Key type, size, allowed usages, sensitivity and
     * extractability are bound to the envelope as AES-GCM AAD, so they cannot
     * be altered in transit and are preserved exactly on unwrap. A target
     * marked non-extractable is rejected with
     * {@link HsmError#KEY_NOT_EXTRACTABLE}, distinct from usage, not-found
     * and destroyed failures.
     */
    public byte[] wrapKey(long sessionHandle, String wrappingKeyId, String targetKeyId) {
        synchronized (lock) {
            requireOperableSession(sessionHandle);
            StoredKey wrappingKey = requireUsableKey(wrappingKeyId, KeyUsage.WRAP);
            StoredKey target = requireUsableKey(targetKeyId, null);
            if (wrappingKey.getKeyType() != KeyType.AES) {
                throw new HsmException(HsmError.INVALID_KEY_TYPE, "wrapping key must be AES");
            }
            if (!target.isExtractable()) {
                throw new HsmException(HsmError.KEY_NOT_EXTRACTABLE,
                        "key " + targetKeyId + " is not extractable");
            }
            byte[] headerBytes = buildEnvelopeHeader(target);
            byte[] wrappedMaterial;
            try {
                wrappedMaterial = crypto.aesGcmEncryptWithIv(
                        unprotect(wrappingKey), unprotect(target), headerBytes);
            } catch (RuntimeException e) {
                throw new HsmException(HsmError.WRAPPING_FAILED, e.getMessage());
            }
            Map<String, Object> envelope = new LinkedHashMap<>();
            envelope.put("header", Base64.getEncoder().encodeToString(headerBytes));
            envelope.put("wrapped", Base64.getEncoder().encodeToString(wrappedMaterial));
            return writeJson(envelope);
        }
    }

    /**
     * Imports a wrapped key under an AES key that permits UNWRAP. When the
     * caller supplies a usage template it must equal the usages embedded in
     * the envelope; otherwise the embedded usages are restored. The imported
     * key is behaviorally equivalent to the wrapped source key.
     */
    public String unwrapKey(long sessionHandle, String wrappingKeyId, byte[] wrapped,
                            String label, Set<KeyUsage> usages) {
        if (wrapped == null || wrapped.length == 0) {
            throw new HsmException(HsmError.INVALID_ARGUMENT, "wrapped blob required");
        }
        synchronized (lock) {
            requireOperableSession(sessionHandle);
            StoredKey wrappingKey = requireUsableKey(wrappingKeyId, KeyUsage.UNWRAP);
            if (wrappingKey.getKeyType() != KeyType.AES) {
                throw new HsmException(HsmError.INVALID_KEY_TYPE, "wrapping key must be AES");
            }
            Map<String, String> envelope;
            byte[] headerBytes;
            byte[] rawKey;
            try {
                envelope = readJson(wrapped, new TypeReference<>() {
                });
                headerBytes = Base64.getDecoder().decode(envelope.get("header"));
                rawKey = crypto.aesGcmDecryptWithIv(unprotect(wrappingKey),
                        Base64.getDecoder().decode(envelope.get("wrapped")), headerBytes);
            } catch (HsmException e) {
                throw e;
            } catch (RuntimeException e) {
                throw new HsmException(HsmError.UNWRAPPING_FAILED, "malformed wrapped blob");
            }
            if (rawKey == null) {
                throw new HsmException(HsmError.UNWRAPPING_FAILED, "wrapped blob cannot be opened");
            }
            try {
                Map<String, Object> header = readJson(headerBytes, new TypeReference<>() {
                });
                KeyType keyType = KeyType.valueOf((String) header.get("keyType"));
                int keyBits = ((Number) header.get("keyBits")).intValue();
                Set<KeyUsage> embeddedUsages = parseUsages(header.get("usages"));
                if (usages != null && !embeddedUsages.equals(normalizeUsages(usages))) {
                    throw new HsmException(HsmError.KEY_USAGE_VIOLATION,
                            "unwrap template differs from wrapped key usages");
                }
                boolean sensitive = Boolean.TRUE.equals(header.get("sensitive"));
                // Envelopes written before extractability was tracked lack the
                // field; those copies stay non-extractable as before.
                boolean extractable = Boolean.TRUE.equals(header.get("extractable"));
                byte[] publicMaterial = header.get("public") == null ? null
                        : Base64.getDecoder().decode((String) header.get("public"));
                String id = newKeyId();
                StoredKey key = new StoredKey(id, safeLabel(label), keyType, keyBits,
                        EnumSet.copyOf(embeddedUsages), sensitive, extractable, System.currentTimeMillis(),
                        protect(id, rawKey), publicMaterial);
                snapshot.getKeys().put(id, key);
                persist(snapshot);
                return id;
            } catch (HsmException e) {
                throw e;
            } catch (RuntimeException e) {
                throw new HsmException(HsmError.UNWRAPPING_FAILED, "malformed wrapped header");
            }
        }
    }

    // ------------------------------------------------------------ internals

    private void persist(TokenSnapshot newSnapshot) {
        store.save(newSnapshot);
        this.snapshot = newSnapshot;
    }

    private void requireInitialized() {
        if (!snapshot.isInitialized()) {
            throw new HsmException(HsmError.TOKEN_NOT_INITIALIZED);
        }
    }

    private void requirePin(String pin, String name) {
        if (pin == null || pin.isBlank()) {
            throw new HsmException(HsmError.INVALID_ARGUMENT, name + " required");
        }
    }

    private void installPin(TokenSnapshot target, UserType userType, String pin) {
        TokenSnapshot.PinRecord record = target.pinRecord(userType);
        byte[] salt = crypto.newSalt();
        record.setSalt(salt);
        record.setHash(crypto.hashPin(pin.toCharArray(), salt));
        record.setFailCount(0);
        record.setLocked(false);
    }

    private void verifyPin(UserType userType, String pin) {
        TokenSnapshot.PinRecord record = snapshot.pinRecord(userType);
        if (record.isLocked()) {
            throw new HsmException(HsmError.PIN_LOCKED,
                    userType + " is locked out until SO unlock");
        }
        byte[] candidate = crypto.hashPin(pin.toCharArray(), record.getSalt());
        if (!MessageDigest.isEqual(candidate, record.getHash())) {
            record.setFailCount(record.getFailCount() + 1);
            if (record.getFailCount() >= maxPinAttempts) {
                record.setLocked(true);
            }
            persist(snapshot);
            throw new HsmException(record.isLocked() ? HsmError.PIN_LOCKED : HsmError.PIN_INCORRECT,
                    "bad PIN; failures=" + record.getFailCount());
        }
        if (record.getFailCount() != 0) {
            record.setFailCount(0);
            persist(snapshot);
        }
    }

    private Session requireOpenSession(long handle) {
        Session session = sessions.get(handle);
        if (session == null || !session.isOpen()) {
            throw new HsmException(HsmError.SESSION_HANDLE_INVALID);
        }
        return session;
    }

    /**
     * Key-object management and cryptographic operations require an unlocked
     * token and a session logged in as the ordinary user. SO sessions are
     * rejected with {@link HsmError#ROLE_REQUIRED}, a reason distinct from
     * {@link HsmError#NOT_LOGGED_IN}, {@link HsmError#SESSION_HANDLE_INVALID}
     * and {@link HsmError#TOKEN_LOCKED}.
     */
    private Session requireOperableSession(long handle) {
        requireInitialized();
        if (snapshot.isLocked()) {
            throw new HsmException(HsmError.TOKEN_LOCKED);
        }
        Session session = requireOpenSession(handle);
        if (!session.isLoggedIn()) {
            throw new HsmException(HsmError.NOT_LOGGED_IN);
        }
        session.requireRole(UserType.USER);
        return session;
    }

    private Set<KeyUsage> normalizeUsages(Set<KeyUsage> usages) {
        if (usages == null || usages.isEmpty()) {
            throw new HsmException(HsmError.INVALID_ARGUMENT, "at least one usage required");
        }
        return EnumSet.copyOf(usages);
    }

    /**
     * Keys are non-extractable unless the caller explicitly opts in to
     * wrapping export; this matches the default stored by earlier versions.
     */
    private boolean resolveExtractable(Boolean extractable) {
        return extractable != null && extractable;
    }

    private String safeLabel(String label) {
        return label == null || label.isBlank() ? "key" : label;
    }

    private String newKeyId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    private StoredKey requireExistingKey(String keyId) {
        StoredKey key = keyId == null ? null : snapshot.getKeys().get(keyId);
        if (key == null) {
            throw new HsmException(HsmError.KEY_NOT_FOUND, keyId);
        }
        if (key.isDestroyed()) {
            throw new HsmException(HsmError.KEY_DESTROYED, keyId);
        }
        return key;
    }

    private StoredKey requireUsableKey(String keyId, KeyUsage usage) {
        StoredKey key = requireExistingKey(keyId);
        if (usage != null && !key.allows(usage)) {
            throw new HsmException(HsmError.KEY_USAGE_VIOLATION,
                    "key " + keyId + " does not allow " + usage);
        }
        return key;
    }

    private void requireData(byte[] data) {
        if (data == null || data.length == 0) {
            throw new HsmException(HsmError.INVALID_ARGUMENT, "data required");
        }
    }

    private byte[] protect(String keyId, byte[] raw) {
        return crypto.aesGcmEncryptWithIv(masterKey, raw, aadForKeyId(keyId));
    }

    private byte[] unprotect(StoredKey key) {
        byte[] raw = crypto.aesGcmDecryptWithIv(masterKey,
                key.getProtectedMaterial(), aadForKeyId(key.getId()));
        if (raw == null) {
            throw new HsmException(HsmError.INTERNAL_ERROR,
                    "protected material of key " + key.getId() + " cannot be recovered");
        }
        return raw;
    }

    private byte[] aadForKeyId(String keyId) {
        return ("hsm-master-key-protection:" + keyId).getBytes(StandardCharsets.UTF_8);
    }

    private int rsaKeyBits(byte[] pkcs8Private) {
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return ((java.security.interfaces.RSAPrivateKey)
                    factory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Private))).getModulus().bitLength();
        } catch (Exception e) {
            throw new HsmException(HsmError.INVALID_ARGUMENT, "invalid RSA private key");
        }
    }

    private Map<String, Object> describe(StoredKey key) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("id", key.getId());
        info.put("label", key.getLabel());
        info.put("keyType", key.getKeyType().name());
        info.put("keyBits", key.getKeyBits());
        info.put("usages", key.getUsages().stream().map(Enum::name).sorted().toList());
        info.put("sensitive", key.isSensitive());
        info.put("extractable", key.isExtractable());
        info.put("destroyed", key.isDestroyed());
        info.put("createdAt", key.getCreatedAt());
        return info;
    }

    public Map<String, Object> status() {
        synchronized (lock) {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("initialized", snapshot.isInitialized());
            result.put("locked", snapshot.isLocked());
            result.put("label", snapshot.getLabel());
            result.put("maxPinAttempts", maxPinAttempts);
            result.put("userFailCount", snapshot.pinRecord(UserType.USER).getFailCount());
            result.put("userPinLocked", snapshot.pinRecord(UserType.USER).isLocked());
            result.put("soFailCount", snapshot.pinRecord(UserType.SO).getFailCount());
            result.put("soPinLocked", snapshot.pinRecord(UserType.SO).isLocked());
            result.put("openSessions", sessions.all().size());
            result.put("keyCount", (int) snapshot.getKeys().values().stream()
                    .filter(key -> !key.isDestroyed()).count());
            return result;
        }
    }

    private byte[] buildEnvelopeHeader(StoredKey target) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("keyType", target.getKeyType().name());
        header.put("keyBits", target.getKeyBits());
        header.put("usages", target.getUsages().stream().map(Enum::name).sorted().toList());
        header.put("sensitive", target.isSensitive());
        header.put("extractable", target.isExtractable());
        header.put("public", target.getPublicMaterial() == null ? null
                : Base64.getEncoder().encodeToString(target.getPublicMaterial()));
        return writeJson(header);
    }

    @SuppressWarnings("unchecked")
    private Set<KeyUsage> parseUsages(Object raw) {
        if (!(raw instanceof java.util.List<?> list) || list.isEmpty()) {
            throw new HsmException(HsmError.UNWRAPPING_FAILED, "wrapped header lacks usages");
        }
        Set<KeyUsage> result = EnumSet.noneOf(KeyUsage.class);
        for (Object item : list) {
            result.add(KeyUsage.valueOf((String) item));
        }
        return result;
    }

    private byte[] writeJson(Object value) {
        try {
            return mapper.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new HsmException(HsmError.INTERNAL_ERROR, e.getMessage());
        }
    }

    private <T> T readJson(byte[] json, TypeReference<T> type) {
        try {
            return mapper.readValue(json, type);
        } catch (Exception e) {
            throw new HsmException(HsmError.INVALID_ARGUMENT, "malformed wrapped envelope");
        }
    }
}
