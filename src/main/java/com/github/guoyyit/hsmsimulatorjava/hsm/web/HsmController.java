package com.github.guoyyit.hsmsimulatorjava.hsm.web;

import com.github.guoyyit.hsmsimulatorjava.hsm.core.HsmToken;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.KeyType;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.KeyUsage;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.UserType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * REST facade exposing the token through PKCS#11-style operations. Binary
 * payloads are transported as Base64 fields.
 */
@RestController
@RequestMapping("/api/hsm")
public class HsmController {

    private final HsmToken token;

    public HsmController(@Value("${hsm.data-dir:./hsm-data}") String dataDir,
                         @Value("${hsm.max-pin-attempts:3}") int maxPinAttempts) {
        this.token = new HsmToken(Path.of(dataDir), maxPinAttempts);
    }

    // ------------------------------------------------------------ lifecycle

    @PostMapping("/initialize")
    public Map<String, Object> initialize(@RequestBody InitRequest request) {
        token.initializeToken(request.soPin(), request.userPin(), request.label());
        return token.status();
    }

    @GetMapping("/status")
    public Map<String, Object> status() {
        return token.status();
    }

    @PostMapping("/lock")
    public Map<String, Object> lock(@RequestBody SessionRequest request) {
        token.lock(request.sessionHandle());
        return token.status();
    }

    @PostMapping("/unlock")
    public Map<String, Object> unlock(@RequestBody UnlockRequest request) {
        token.unlock(request.soPin());
        return token.status();
    }

    // ------------------------------------------------------------- sessions

    @PostMapping("/sessions")
    public Map<String, Object> openSession() {
        long handle = token.openSession();
        return Map.of("sessionHandle", handle);
    }

    @DeleteMapping("/sessions/{handle}")
    public Map<String, Object> closeSession(@PathVariable long handle) {
        token.closeSession(handle);
        return Map.of("closed", handle);
    }

    /**
     * Drops every open session at once. Only session state is affected; the
     * lock flag, PIN counters and key objects are left untouched.
     */
    @DeleteMapping("/sessions")
    public Map<String, Object> closeAllSessions() {
        token.closeAllSessions();
        return Map.of("closedAll", true);
    }

    @PostMapping("/sessions/{handle}/login")
    public Map<String, Object> login(@PathVariable long handle, @RequestBody LoginRequest request) {
        token.login(handle, UserType.valueOf(request.role()), request.pin());
        return Map.of("sessionHandle", handle, "role", request.role());
    }

    @PostMapping("/sessions/{handle}/logout")
    public Map<String, Object> logout(@PathVariable long handle) {
        token.logout(handle);
        return Map.of("sessionHandle", handle, "loggedOut", true);
    }

    @GetMapping("/sessions/{handle}")
    public Map<String, Object> sessionInfo(@PathVariable long handle) {
        UserType role = token.currentRole(handle);
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("sessionHandle", handle);
        info.put("role", role == null ? null : role.name());
        info.put("loggedIn", role != null);
        return info;
    }

    // ----------------------------------------------------------------- keys

    @PostMapping("/keys/generate")
    public Map<String, Object> generateKey(@RequestBody GenerateKeyRequest request) {
        String id = token.generateKey(request.sessionHandle(),
                KeyType.valueOf(request.keyType()), request.bits(),
                request.label(), parseUsages(request.usages()), request.extractable());
        return token.getKeyInfo(request.sessionHandle(), id);
    }

    @PostMapping("/keys/import")
    public Map<String, Object> importKey(@RequestBody ImportKeyRequest request) {
        Base64.Decoder decoder = Base64.getDecoder();
        String id = token.importKey(request.sessionHandle(),
                KeyType.valueOf(request.keyType()), request.label(),
                parseUsages(request.usages()), request.sensitive(),
                decoder.decode(request.material()),
                request.publicMaterial() == null ? null : decoder.decode(request.publicMaterial()),
                request.extractable());
        return token.getKeyInfo(request.sessionHandle(), id);
    }

    @GetMapping("/keys/{id}")
    public Map<String, Object> keyInfo(@PathVariable String id, @RequestParam long sessionHandle) {
        return token.getKeyInfo(sessionHandle, id);
    }

    @GetMapping("/keys/{id}/public")
    public Map<String, Object> exportPublicKey(@PathVariable String id, @RequestParam long sessionHandle) {
        return Map.of("id", id,
                "publicMaterial", Base64.getEncoder().encodeToString(token.exportPublicKey(sessionHandle, id)));
    }

    @DeleteMapping("/keys/{id}")
    public Map<String, Object> destroyKey(@PathVariable String id, @RequestParam long sessionHandle) {
        token.destroyKey(sessionHandle, id);
        return Map.of("destroyed", id);
    }

    // --------------------------------------------------------------- crypto

    @PostMapping("/sign")
    public Map<String, Object> sign(@RequestBody KeyDataRequest request) {
        return Map.of("signature",
                Base64.getEncoder().encodeToString(token.sign(
                        request.sessionHandle(), request.keyId(), decode(request.data()))));
    }

    @PostMapping("/verify")
    public Map<String, Object> verify(@RequestBody VerifyRequest request) {
        boolean valid = token.verify(request.sessionHandle(), request.keyId(),
                decode(request.data()), decode(request.signature()));
        return Map.of("valid", valid);
    }

    @PostMapping("/encrypt")
    public Map<String, Object> encrypt(@RequestBody KeyDataRequest request) {
        return Map.of("ciphertext",
                Base64.getEncoder().encodeToString(token.encrypt(
                        request.sessionHandle(), request.keyId(), decode(request.data()))));
    }

    @PostMapping("/decrypt")
    public Map<String, Object> decrypt(@RequestBody KeyCiphertextRequest request) {
        return Map.of("plaintext",
                Base64.getEncoder().encodeToString(token.decrypt(
                        request.sessionHandle(), request.keyId(), decode(request.ciphertext()))));
    }

    @PostMapping("/digest")
    public Map<String, Object> digest(@RequestBody DigestRequest request) {
        return Map.of("digest",
                Base64.getEncoder().encodeToString(token.digest(
                        request.sessionHandle(), decode(request.data()))));
    }

    @PostMapping("/keys/wrap")
    public Map<String, Object> wrap(@RequestBody WrapRequest request) {
        return Map.of("wrapped",
                Base64.getEncoder().encodeToString(token.wrapKey(
                        request.sessionHandle(), request.wrappingKeyId(), request.targetKeyId())));
    }

    @PostMapping("/keys/unwrap")
    public Map<String, Object> unwrap(@RequestBody UnwrapRequest request) {
        String id = token.unwrapKey(request.sessionHandle(), request.wrappingKeyId(),
                decode(request.wrapped()), request.label(), parseUsages(request.usages()));
        return token.getKeyInfo(request.sessionHandle(), id);
    }

    public record InitRequest(String soPin, String userPin, String label) {
    }

    public record SessionRequest(long sessionHandle) {
    }

    public record UnlockRequest(String soPin) {
    }

    public record LoginRequest(String role, String pin) {
    }

    /**
     * {@code extractable} is optional; when absent the token default
     * (non-extractable) applies, so existing clients need no changes.
     */
    public record GenerateKeyRequest(long sessionHandle, String keyType, int bits,
                                     String label, Set<String> usages, Boolean extractable) {
    }

    public record ImportKeyRequest(long sessionHandle, String keyType, String label,
                                   Set<String> usages, boolean sensitive,
                                   String material, String publicMaterial, Boolean extractable) {
    }

    public record KeyDataRequest(long sessionHandle, String keyId, String data) {
    }

    public record KeyCiphertextRequest(long sessionHandle, String keyId, String ciphertext) {
    }

    public record VerifyRequest(long sessionHandle, String keyId, String data, String signature) {
    }

    public record DigestRequest(long sessionHandle, String data) {
    }

    public record WrapRequest(long sessionHandle, String wrappingKeyId, String targetKeyId) {
    }

    public record UnwrapRequest(long sessionHandle, String wrappingKeyId, String wrapped,
                                String label, Set<String> usages) {
    }

    private Set<KeyUsage> parseUsages(Set<String> raw) {
        if (raw == null || raw.isEmpty()) {
            throw new IllegalArgumentException("usages required");
        }
        return raw.stream().map(KeyUsage::valueOf).collect(Collectors.toCollection(java.util.LinkedHashSet::new));
    }

    private byte[] decode(String base64) {
        if (base64 == null || base64.isEmpty()) {
            throw new IllegalArgumentException("base64 payload required");
        }
        return Base64.getDecoder().decode(base64);
    }
}
