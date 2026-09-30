package com.github.guoyyit.hsmsimulatorjava.hsm;

import com.github.guoyyit.hsmsimulatorjava.hsm.crypto.CryptoEngine;
import com.github.guoyyit.hsmsimulatorjava.hsm.persistence.FileStateStore;
import com.github.guoyyit.hsmsimulatorjava.hsm.persistence.StateStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKey;

@Service
public class HsmService {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String WRAP_ALG = "RSA-OAEP-SHA256+AES256-GCM";
    private static final int WRAP_VERSION = 1;
    private static final byte[] WRAP_AAD = "HSM-KEY-WRAP-V1".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    private static final int PBKDF2_ITERATIONS = 120_000;
    private static final int PBKDF2_SALT_LENGTH = 16;
    private static final int PBKDF2_KEY_LENGTH = 256;

    private final StateStore store;
    private final CryptoEngine cryptoEngine;
    private final SessionManager sessionManager;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
    private TokenState state;

    @org.springframework.beans.factory.annotation.Autowired
    public HsmService(@Value("${hsm.data.dir:./hsm-data}") String dataDir) {
        this(Path.of(dataDir), new CryptoEngine(), new SessionManager());
    }

    HsmService(Path dataDir) {
        this(dataDir, new CryptoEngine(), new SessionManager());
    }

    HsmService(Path dataDir, CryptoEngine cryptoEngine, SessionManager sessionManager) {
        this(new FileStateStore(dataDir), cryptoEngine, sessionManager);
    }

    HsmService(StateStore store, CryptoEngine cryptoEngine, SessionManager sessionManager) {
        this.store = store;
        this.cryptoEngine = cryptoEngine;
        this.sessionManager = sessionManager;
        this.state = store.load();
    }

    public void initToken(String soPin, String userPin) {
        requirePin(soPin, "soPin");
        requirePin(userPin, "userPin");
        lock.writeLock().lock();
        try {
            if (state.isInitialized()) {
                throw new HsmException(HsmErrorCode.TOKEN_ALREADY_INITIALIZED,
                        "Token is already initialized");
            }
            state.setInitialized(true);
            state.setLocked(false);
            state.setSoPinHash(hashPin(soPin));
            state.setUserPinHash(hashPin(userPin));
            state.setSoFailures(0);
            state.setUserFailures(0);
            state.setSoLocked(false);
            state.setUserLocked(false);
            state.getKeys().clear();
            persist();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public TokenStatus getTokenStatus() {
        lock.readLock().lock();
        try {
            return new TokenStatus(
                    state.isInitialized(),
                    state.isLocked(),
                    state.isSoLocked(),
                    state.isUserLocked(),
                    state.getSoFailures(),
                    state.getUserFailures(),
                    state.getMaxAttempts(),
                    countLiveKeys(),
                    sessionManager.sessionCount());
        } finally {
            lock.readLock().unlock();
        }
    }

    public void lockToken(String sessionId) {
        lock.writeLock().lock();
        try {
            requireInitialized();
            requireSession(sessionId, Role.SO);
            state.setLocked(true);
            sessionManager.closeAllSessions();
            persist();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void unlockToken(String soPin) {
        requirePin(soPin, "soPin");
        lock.writeLock().lock();
        try {
            requireInitialized();
            verifyPin(Role.SO, soPin);
            state.setLocked(false);
            state.setUserLocked(false);
            state.setUserFailures(0);
            persist();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public String openSession() {
        lock.readLock().lock();
        try {
            requireInitialized();
            requireNotLocked();
            return sessionManager.openSession().getId();
        } finally {
            lock.readLock().unlock();
        }
    }

    public void closeSession(String sessionId) {
        if (!sessionManager.closeSession(sessionId)) {
            throw new HsmException(HsmErrorCode.SESSION_NOT_FOUND,
                    "Session not found: " + sessionId);
        }
    }

    public void closeAllSessions() {
        sessionManager.closeAllSessions();
    }

    public void login(String sessionId, Role role, String pin) {
        Objects.requireNonNull(role, "role");
        requirePin(pin, "pin");
        Session session = requireOpenSession(sessionId);
        lock.writeLock().lock();
        try {
            requireInitialized();
            requireNotLocked();
            if (session.getRole() != null) {
                throw new HsmException(HsmErrorCode.ACCESS_DENIED,
                        "Session is already logged in");
            }
            try {
                verifyPin(role, pin);
                session.setRole(role);
            } finally {
                persist();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void logout(String sessionId) {
        Session session = requireOpenSession(sessionId);
        session.setRole(null);
    }

    public KeyObject generateKey(String sessionId, KeyType keyType, String label,
                                 Set<KeyUsage> usages, boolean extractable) {
        Objects.requireNonNull(keyType, "keyType");
        lock.writeLock().lock();
        try {
            requireInitialized();
            requireNotLocked();
            requireSession(sessionId, Role.USER);
            KeyObject key = new KeyObject();
            key.setId(java.util.UUID.randomUUID().toString());
            key.setLabel(label == null ? keyType.name() + "-key" : label);
            key.setKeyType(keyType);
            key.setUsages(normalizeUsages(usages));
            key.setExtractable(extractable);
            if (keyType == KeyType.RSA) {
                java.security.KeyPair pair = cryptoEngine.generateRsaKeyPair();
                key.setSensitive(false);
                key.setPrivateMaterial(pair.getPrivate().getEncoded());
                key.setPublicMaterial(pair.getPublic().getEncoded());
            } else if (keyType == KeyType.AES) {
                key.setSensitive(true);
                key.setPrivateMaterial(cryptoEngine.generateAesKey().getEncoded());
            } else {
                throw new HsmException(HsmErrorCode.UNSUPPORTED_OPERATION,
                        "Unsupported key type: " + keyType);
            }
            state.getKeys().put(key.getId(), key);
            persist();
            return sanitize(key);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public KeyObject importSecretKey(String sessionId, String label, byte[] material,
                                     Set<KeyUsage> usages, boolean extractable) {
        if (material == null || (material.length != 16 && material.length != 32)) {
            throw new HsmException(HsmErrorCode.INVALID_ARGUMENT,
                    "AES key material must be 16 or 32 bytes");
        }
        lock.writeLock().lock();
        try {
            requireInitialized();
            requireNotLocked();
            requireSession(sessionId, Role.USER);
            cryptoEngine.aesKeyFromBytes(material);
            KeyObject key = new KeyObject();
            key.setId(java.util.UUID.randomUUID().toString());
            key.setLabel(label == null ? "imported-aes-key" : label);
            key.setKeyType(KeyType.AES);
            key.setUsages(normalizeUsages(usages));
            key.setSensitive(true);
            key.setExtractable(extractable);
            key.setPrivateMaterial(material.clone());
            state.getKeys().put(key.getId(), key);
            persist();
            return sanitize(key);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public KeyObject getKey(String sessionId, String keyId) {
        lock.readLock().lock();
        try {
            requireInitialized();
            requireNotLocked();
            requireSession(sessionId, Role.USER);
            return sanitize(requireLiveKey(keyId));
        } finally {
            lock.readLock().unlock();
        }
    }

    public List<KeyObject> listKeys(String sessionId) {
        lock.readLock().lock();
        try {
            requireInitialized();
            requireNotLocked();
            requireSession(sessionId, Role.USER);
            return state.getKeys().values().stream()
                    .filter(key -> !key.isDestroyed())
                    .map(HsmService::sanitize)
                    .toList();
        } finally {
            lock.readLock().unlock();
        }
    }

    public void destroyKey(String sessionId, String keyId) {
        lock.writeLock().lock();
        try {
            requireInitialized();
            requireNotLocked();
            requireSession(sessionId, Role.USER);
            KeyObject key = requireLiveKey(keyId);
            key.setDestroyed(true);
            key.setPrivateMaterial(null);
            key.setPublicMaterial(null);
            persist();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public byte[] sign(String sessionId, String keyId, byte[] data) {
        requireData(data);
        lock.readLock().lock();
        try {
            requireInitialized();
            requireNotLocked();
            requireSession(sessionId, Role.USER);
            KeyObject key = requireLiveKey(keyId);
            requireUsage(key, KeyUsage.SIGN);
            return cryptoEngine.signRsa(
                    cryptoEngine.rsaPrivateFromPkcs8(key.getPrivateMaterial()), data);
        } finally {
            lock.readLock().unlock();
        }
    }

    public boolean verify(String sessionId, String keyId, byte[] data, byte[] signature) {
        requireData(data);
        requireData(signature);
        lock.readLock().lock();
        try {
            requireInitialized();
            requireNotLocked();
            requireSession(sessionId, Role.USER);
            KeyObject key = requireLiveKey(keyId);
            requireUsage(key, KeyUsage.VERIFY);
            return cryptoEngine.verifyRsa(
                    cryptoEngine.rsaPublicFromX509(key.getPublicMaterial()), data, signature);
        } finally {
            lock.readLock().unlock();
        }
    }

    public byte[] encrypt(String sessionId, String keyId, byte[] data) {
        requireData(data);
        lock.readLock().lock();
        try {
            requireInitialized();
            requireNotLocked();
            requireSession(sessionId, Role.USER);
            KeyObject key = requireLiveKey(keyId);
            requireUsage(key, KeyUsage.ENCRYPT);
            if (key.getKeyType() == KeyType.RSA) {
                return cryptoEngine.rsaEncrypt(
                        cryptoEngine.rsaPublicFromX509(key.getPublicMaterial()), data);
            }
            return cryptoEngine.aesGcmEncrypt(
                    cryptoEngine.aesKeyFromBytes(key.getPrivateMaterial()), data, null);
        } finally {
            lock.readLock().unlock();
        }
    }

    public byte[] decrypt(String sessionId, String keyId, byte[] ciphertext) {
        requireData(ciphertext);
        lock.readLock().lock();
        try {
            requireInitialized();
            requireNotLocked();
            requireSession(sessionId, Role.USER);
            KeyObject key = requireLiveKey(keyId);
            requireUsage(key, KeyUsage.DECRYPT);
            if (key.getKeyType() == KeyType.RSA) {
                return cryptoEngine.rsaDecrypt(
                        cryptoEngine.rsaPrivateFromPkcs8(key.getPrivateMaterial()), ciphertext);
            }
            return cryptoEngine.aesGcmDecrypt(
                    cryptoEngine.aesKeyFromBytes(key.getPrivateMaterial()), ciphertext, null);
        } finally {
            lock.readLock().unlock();
        }
    }

    public byte[] digest(String sessionId, byte[] data) {
        requireData(data);
        lock.readLock().lock();
        try {
            requireInitialized();
            requireNotLocked();
            requireSession(sessionId, Role.USER);
            return cryptoEngine.sha256(data);
        } finally {
            lock.readLock().unlock();
        }
    }

    public WrappedKey wrapKey(String sessionId, String wrappingKeyId, String keyId) {
        lock.readLock().lock();
        try {
            requireInitialized();
            requireNotLocked();
            requireSession(sessionId, Role.USER);
            KeyObject wrappingKey = requireLiveKey(wrappingKeyId);
            requireUsage(wrappingKey, KeyUsage.WRAP);
            if (wrappingKey.getKeyType() != KeyType.RSA) {
                throw new HsmException(HsmErrorCode.UNSUPPORTED_OPERATION,
                        "Only RSA keys may act as wrapping keys");
            }
            KeyObject target = requireLiveKey(keyId);
            if (!target.isExtractable()) {
                throw new HsmException(HsmErrorCode.KEY_NOT_EXTRACTABLE,
                        "Key " + keyId + " is not extractable");
            }
            byte[] envelope = serializeEnvelope(target);
            SecretKey contentKey = cryptoEngine.generateAesKey();
            byte[] ivCiphertext = cryptoEngine.aesGcmEncrypt(
                    contentKey, envelope, WRAP_AAD);
            byte[] iv = new byte[12];
            byte[] ciphertext = new byte[ivCiphertext.length - 12];
            System.arraycopy(ivCiphertext, 0, iv, 0, 12);
            System.arraycopy(ivCiphertext, 12, ciphertext, 0, ciphertext.length);
            byte[] encryptedCek = cryptoEngine.rsaEncrypt(
                    cryptoEngine.rsaPublicFromX509(wrappingKey.getPublicMaterial()),
                    contentKey.getEncoded());
            return new WrappedKey(WRAP_VERSION, WRAP_ALG, wrappingKeyId,
                    iv, encryptedCek, ciphertext);
        } finally {
            lock.readLock().unlock();
        }
    }

    public KeyObject unwrapKey(String sessionId, String wrappingKeyId, WrappedKey wrapped) {
        if (wrapped == null || wrapped.iv() == null || wrapped.encryptedCek() == null
                || wrapped.ciphertext() == null) {
            throw new HsmException(HsmErrorCode.INVALID_ARGUMENT,
                    "Wrapped key payload is incomplete");
        }
        lock.writeLock().lock();
        try {
            requireInitialized();
            requireNotLocked();
            requireSession(sessionId, Role.USER);
            KeyObject wrappingKey = requireLiveKey(wrappingKeyId);
            requireUsage(wrappingKey, KeyUsage.UNWRAP);
            if (wrappingKey.getKeyType() != KeyType.RSA) {
                throw new HsmException(HsmErrorCode.UNSUPPORTED_OPERATION,
                        "Only RSA keys may act as wrapping keys");
            }
            if (!wrappingKeyId.equals(wrapped.wrappingKeyId())) {
                throw new HsmException(HsmErrorCode.INVALID_ARGUMENT,
                        "Wrapping key id does not match the payload");
            }
            byte[] rawCek = cryptoEngine.rsaDecrypt(
                    cryptoEngine.rsaPrivateFromPkcs8(wrappingKey.getPrivateMaterial()),
                    wrapped.encryptedCek());
            byte[] ivCiphertext = new byte[wrapped.iv().length + wrapped.ciphertext().length];
            System.arraycopy(wrapped.iv(), 0, ivCiphertext, 0, wrapped.iv().length);
            System.arraycopy(wrapped.ciphertext(), 0, ivCiphertext,
                    wrapped.iv().length, wrapped.ciphertext().length);
            byte[] envelopeBytes = cryptoEngine.aesGcmDecrypt(
                    cryptoEngine.aesKeyFromBytes(rawCek), ivCiphertext, WRAP_AAD);
            KeyEnvelope envelope = deserializeEnvelope(envelopeBytes);
            KeyObject key = new KeyObject();
            key.setId(java.util.UUID.randomUUID().toString());
            key.setLabel(envelope.label());
            key.setKeyType(envelope.keyType());
            key.setUsages(envelope.usages());
            key.setSensitive(envelope.sensitive());
            key.setExtractable(envelope.extractable());
            key.setPrivateMaterial(envelope.privateMaterial());
            key.setPublicMaterial(envelope.publicMaterial());
            state.getKeys().put(key.getId(), key);
            persist();
            return sanitize(key);
        } finally {
            lock.writeLock().unlock();
        }
    }

    private static byte[] serializeEnvelope(KeyObject key) {
        try {
            KeyEnvelope envelope = new KeyEnvelope(
                    WRAP_VERSION,
                    key.getKeyType(),
                    key.getLabel(),
                    key.getUsages(),
                    key.isSensitive(),
                    key.isExtractable(),
                    key.getPrivateMaterial(),
                    key.getPublicMaterial());
            return OBJECT_MAPPER.writeValueAsBytes(envelope);
        } catch (Exception e) {
            throw new HsmException(HsmErrorCode.CRYPTO_FAILED,
                    "Failed to serialize key envelope", e);
        }
    }

    private static KeyEnvelope deserializeEnvelope(byte[] bytes) {
        try {
            KeyEnvelope envelope = OBJECT_MAPPER.readValue(bytes, KeyEnvelope.class);
            if (envelope.version() != WRAP_VERSION || envelope.keyType() == null
                    || envelope.usages() == null || envelope.usages().isEmpty()) {
                throw new HsmException(HsmErrorCode.INVALID_ARGUMENT,
                        "Invalid key envelope");
            }
            return envelope;
        } catch (HsmException e) {
            throw e;
        } catch (Exception e) {
            throw new HsmException(HsmErrorCode.INVALID_ARGUMENT,
                    "Invalid key envelope", e);
        }
    }

    public record KeyEnvelope(
            int version,
            KeyType keyType,
            String label,
            java.util.Set<KeyUsage> usages,
            boolean sensitive,
            boolean extractable,
            byte[] privateMaterial,
            byte[] publicMaterial
    ) {
    }

    private static void requireData(byte[] data) {
        if (data == null || data.length == 0) {
            throw new HsmException(HsmErrorCode.INVALID_ARGUMENT,
                    "Data must not be empty");
        }
    }

    private static void requireUsage(KeyObject key, KeyUsage usage) {
        if (!key.getUsages().contains(usage)) {
            throw new HsmException(HsmErrorCode.USAGE_NOT_ALLOWED,
                    "Key " + key.getId() + " is not allowed for " + usage);
        }
    }

    private static java.util.EnumSet<KeyUsage> normalizeUsages(Set<KeyUsage> usages) {
        if (usages == null || usages.isEmpty()) {
            throw new HsmException(HsmErrorCode.INVALID_ARGUMENT,
                    "At least one key usage is required");
        }
        return java.util.EnumSet.copyOf(usages);
    }

    private KeyObject requireLiveKey(String keyId) {
        KeyObject key = state.getKeys().get(keyId);
        if (key == null || key.isDestroyed()) {
            throw new HsmException(HsmErrorCode.KEY_NOT_FOUND,
                    "Key not found or destroyed: " + keyId);
        }
        return key;
    }

    private static KeyObject sanitize(KeyObject key) {
        KeyObject view = new KeyObject();
        view.setId(key.getId());
        view.setLabel(key.getLabel());
        view.setKeyType(key.getKeyType());
        view.setUsages(key.getUsages());
        view.setSensitive(key.isSensitive());
        view.setExtractable(key.isExtractable());
        view.setDestroyed(key.isDestroyed());
        view.setPublicMaterial(key.getPublicMaterial());
        return view;
    }

    private void persist() {
        store.save(state);
    }

    private void requireInitialized() {
        if (!state.isInitialized()) {
            throw new HsmException(HsmErrorCode.TOKEN_NOT_INITIALIZED,
                    "Token has not been initialized");
        }
    }

    private void requireNotLocked() {
        if (state.isLocked()) {
            throw new HsmException(HsmErrorCode.TOKEN_LOCKED, "Token is locked");
        }
    }

    private void requirePin(String pin, String name) {
        if (pin == null || pin.isEmpty()) {
            throw new HsmException(HsmErrorCode.INVALID_ARGUMENT,
                    name + " must not be empty");
        }
    }

    private Session requireOpenSession(String sessionId) {
        Session session = sessionManager.getSession(sessionId);
        if (session == null) {
            throw new HsmException(HsmErrorCode.SESSION_NOT_FOUND,
                    "Session not found: " + sessionId);
        }
        return session;
    }

    private Session requireSession(String sessionId, Role role) {
        Session session = requireOpenSession(sessionId);
        if (session.getRole() == null) {
            throw new HsmException(HsmErrorCode.NOT_LOGGED_IN,
                    "Session is not logged in");
        }
        if (session.getRole() != role) {
            throw new HsmException(HsmErrorCode.ACCESS_DENIED,
                    "Operation requires role " + role);
        }
        return session;
    }

    private void verifyPin(Role role, String pin) {
        boolean roleLocked = role == Role.SO ? state.isSoLocked() : state.isUserLocked();
        if (roleLocked) {
            throw new HsmException(HsmErrorCode.PIN_LOCKED, role + " PIN is locked");
        }
        String storedHash = role == Role.SO ? state.getSoPinHash() : state.getUserPinHash();
        if (matches(pin, storedHash)) {
            if (role == Role.SO) {
                state.setSoFailures(0);
            } else {
                state.setUserFailures(0);
            }
            return;
        }
        int failures = role == Role.SO
                ? state.getSoFailures() + 1
                : state.getUserFailures() + 1;
        if (role == Role.SO) {
            state.setSoFailures(failures);
        } else {
            state.setUserFailures(failures);
        }
        if (failures >= state.getMaxAttempts()) {
            if (role == Role.SO) {
                state.setSoLocked(true);
            } else {
                state.setUserLocked(true);
            }
            throw new HsmException(HsmErrorCode.PIN_LOCKED,
                    role + " PIN locked after " + failures + " failed attempts");
        }
        throw new HsmException(HsmErrorCode.INVALID_PIN,
                "Invalid PIN (attempt " + failures + "/" + state.getMaxAttempts() + ")");
    }

    private int countLiveKeys() {
        int count = 0;
        for (KeyObject key : state.getKeys().values()) {
            if (!key.isDestroyed()) {
                count++;
            }
        }
        return count;
    }

    private static String hashPin(String pin) {
        try {
            byte[] salt = new byte[PBKDF2_SALT_LENGTH];
            new SecureRandom().nextBytes(salt);
            KeySpec spec = new PBEKeySpec(pin.toCharArray(), salt,
                    PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);
            byte[] hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
            return PBKDF2_ITERATIONS + ":"
                    + Base64.getEncoder().encodeToString(salt) + ":"
                    + Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new HsmException(HsmErrorCode.CRYPTO_FAILED, "PIN hashing failed", e);
        }
    }

    private static boolean matches(String pin, String stored) {
        try {
            String[] parts = stored.split(":", 3);
            int iterations = Integer.parseInt(parts[0]);
            byte[] salt = Base64.getDecoder().decode(parts[1]);
            byte[] expected = Base64.getDecoder().decode(parts[2]);
            KeySpec spec = new PBEKeySpec(pin.toCharArray(), salt,
                    iterations, expected.length * 8);
            byte[] actual = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
            return MessageDigest.isEqual(expected, actual);
        } catch (Exception e) {
            throw new HsmException(HsmErrorCode.CRYPTO_FAILED, "PIN verification failed", e);
        }
    }
}
