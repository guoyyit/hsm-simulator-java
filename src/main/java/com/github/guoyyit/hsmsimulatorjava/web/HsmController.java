package com.github.guoyyit.hsmsimulatorjava.web;

import com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode;
import com.github.guoyyit.hsmsimulatorjava.hsm.HsmException;
import com.github.guoyyit.hsmsimulatorjava.hsm.HsmService;
import com.github.guoyyit.hsmsimulatorjava.hsm.KeyObject;
import com.github.guoyyit.hsmsimulatorjava.hsm.KeyType;
import com.github.guoyyit.hsmsimulatorjava.hsm.KeyUsage;
import com.github.guoyyit.hsmsimulatorjava.hsm.Role;
import com.github.guoyyit.hsmsimulatorjava.hsm.TokenStatus;
import com.github.guoyyit.hsmsimulatorjava.hsm.WrappedKey;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/hsm")
public class HsmController {

    private final HsmService hsmService;

    public HsmController(HsmService hsmService) {
        this.hsmService = hsmService;
    }

    public record InitRequest(String soPin, String userPin) {
    }

    public record LoginRequest(String role, String pin) {
    }

    public record GenerateKeyRequest(String keyType, String label,
                                    Set<KeyUsage> usages, boolean extractable) {
    }

    public record ImportKeyRequest(String label, String material,
                                   Set<KeyUsage> usages, boolean extractable) {
    }

    public record DataRequest(String data) {
    }

    public record VerifyRequest(String data, String signature) {
    }

    public record WrapRequest(String wrappingKeyId) {
    }

    public record UnwrapRequest(String wrappingKeyId, WrappedKeyDto wrappedKey) {
    }

    public record WrappedKeyDto(int version, String alg, String wrappingKeyId,
                                String iv, String encryptedCek, String ciphertext) {
    }

    @PostMapping("/init")
    public Map<String, String> init(@RequestBody InitRequest request) {
        hsmService.initToken(request.soPin(), request.userPin());
        return Map.of("status", "initialized");
    }

    @GetMapping("/status")
    public TokenStatus status() {
        return hsmService.getTokenStatus();
    }

    @PostMapping("/lock/{sessionId}")
    public Map<String, String> lock(@PathVariable String sessionId) {
        hsmService.lockToken(sessionId);
        return Map.of("status", "locked");
    }

    @PostMapping("/unlock")
    public Map<String, String> unlock(@RequestBody LoginRequest request) {
        hsmService.unlockToken(request.pin());
        return Map.of("status", "unlocked");
    }

    @PostMapping("/sessions")
    public Map<String, String> openSession() {
        return Map.of("sessionId", hsmService.openSession());
    }

    @DeleteMapping("/sessions/{sessionId}")
    public Map<String, String> closeSession(@PathVariable String sessionId) {
        hsmService.closeSession(sessionId);
        return Map.of("status", "closed");
    }

    @DeleteMapping("/sessions")
    public Map<String, String> closeAllSessions() {
        hsmService.closeAllSessions();
        return Map.of("status", "closed");
    }

    @PostMapping("/sessions/{sessionId}/login")
    public Map<String, String> login(@PathVariable String sessionId,
                                     @RequestBody LoginRequest request) {
        hsmService.login(sessionId, parseRole(request.role()), request.pin());
        return Map.of("status", "logged-in", "role", request.role().toUpperCase());
    }

    @PostMapping("/sessions/{sessionId}/logout")
    public Map<String, String> logout(@PathVariable String sessionId) {
        hsmService.logout(sessionId);
        return Map.of("status", "logged-out");
    }

    @PostMapping("/keys")
    public KeyObject generateKey(@RequestHeader("X-Session-Id") String sessionId,
                                 @RequestBody GenerateKeyRequest request) {
        KeyType keyType = parseKeyType(request.keyType());
        return hsmService.generateKey(sessionId, keyType, request.label(),
                request.usages(), request.extractable());
    }

    @PostMapping("/keys/import")
    public KeyObject importKey(@RequestHeader("X-Session-Id") String sessionId,
                               @RequestBody ImportKeyRequest request) {
        return hsmService.importSecretKey(sessionId, request.label(),
                decodeBase64(request.material(), "material"),
                request.usages(), request.extractable());
    }

    @GetMapping("/keys")
    public List<KeyObject> listKeys(@RequestHeader("X-Session-Id") String sessionId) {
        return hsmService.listKeys(sessionId);
    }

    @GetMapping("/keys/{keyId}")
    public KeyObject getKey(@RequestHeader("X-Session-Id") String sessionId,
                            @PathVariable String keyId) {
        return hsmService.getKey(sessionId, keyId);
    }

    @DeleteMapping("/keys/{keyId}")
    public Map<String, String> destroyKey(@RequestHeader("X-Session-Id") String sessionId,
                                          @PathVariable String keyId) {
        hsmService.destroyKey(sessionId, keyId);
        return Map.of("status", "destroyed");
    }

    @PostMapping("/keys/{keyId}/sign")
    public Map<String, String> sign(@RequestHeader("X-Session-Id") String sessionId,
                                    @PathVariable String keyId,
                                    @RequestBody DataRequest request) {
        byte[] signature = hsmService.sign(sessionId, keyId,
                request.data().getBytes(StandardCharsets.UTF_8));
        return Map.of("signature", encodeBase64(signature));
    }

    @PostMapping("/keys/{keyId}/verify")
    public Map<String, Boolean> verify(@RequestHeader("X-Session-Id") String sessionId,
                                       @PathVariable String keyId,
                                       @RequestBody VerifyRequest request) {
        boolean valid = hsmService.verify(sessionId, keyId,
                request.data().getBytes(StandardCharsets.UTF_8),
                decodeBase64(request.signature(), "signature"));
        return Map.of("valid", valid);
    }

    @PostMapping("/keys/{keyId}/encrypt")
    public Map<String, String> encrypt(@RequestHeader("X-Session-Id") String sessionId,
                                       @PathVariable String keyId,
                                       @RequestBody DataRequest request) {
        byte[] ciphertext = hsmService.encrypt(sessionId, keyId,
                request.data().getBytes(StandardCharsets.UTF_8));
        return Map.of("ciphertext", encodeBase64(ciphertext));
    }

    @PostMapping("/keys/{keyId}/decrypt")
    public Map<String, String> decrypt(@RequestHeader("X-Session-Id") String sessionId,
                                       @PathVariable String keyId,
                                       @RequestBody DataRequest request) {
        byte[] plaintext = hsmService.decrypt(sessionId, keyId,
                decodeBase64(request.data(), "data"));
        return Map.of("data", new String(plaintext, StandardCharsets.UTF_8));
    }

    @PostMapping("/digest")
    public Map<String, String> digest(@RequestHeader("X-Session-Id") String sessionId,
                                      @RequestBody DataRequest request) {
        byte[] hash = hsmService.digest(sessionId, request.data().getBytes(StandardCharsets.UTF_8));
        return Map.of("digest", encodeBase64(hash));
    }

    @PostMapping("/keys/{keyId}/wrap")
    public WrappedKeyDto wrap(@RequestHeader("X-Session-Id") String sessionId,
                              @PathVariable String keyId,
                              @RequestBody WrapRequest request) {
        WrappedKey wrapped = hsmService.wrapKey(sessionId, request.wrappingKeyId(), keyId);
        return new WrappedKeyDto(wrapped.version(), wrapped.alg(), wrapped.wrappingKeyId(),
                encodeBase64(wrapped.iv()), encodeBase64(wrapped.encryptedCek()),
                encodeBase64(wrapped.ciphertext()));
    }

    @PostMapping("/keys/unwrap")
    public KeyObject unwrap(@RequestHeader("X-Session-Id") String sessionId,
                            @RequestBody UnwrapRequest request) {
        WrappedKeyDto dto = request.wrappedKey();
        WrappedKey wrapped = new WrappedKey(dto.version(), dto.alg(), dto.wrappingKeyId(),
                decodeBase64(dto.iv(), "iv"),
                decodeBase64(dto.encryptedCek(), "encryptedCek"),
                decodeBase64(dto.ciphertext(), "ciphertext"));
        return hsmService.unwrapKey(sessionId, request.wrappingKeyId(), wrapped);
    }

    private static Role parseRole(String role) {
        if (role == null) {
            throw new HsmException(HsmErrorCode.INVALID_ARGUMENT, "role is required");
        }
        try {
            return Role.valueOf(role.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new HsmException(HsmErrorCode.INVALID_ARGUMENT,
                    "Unknown role: " + role);
        }
    }

    private static KeyType parseKeyType(String keyType) {
        if (keyType == null) {
            throw new HsmException(HsmErrorCode.INVALID_ARGUMENT, "keyType is required");
        }
        try {
            return KeyType.valueOf(keyType.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new HsmException(HsmErrorCode.INVALID_ARGUMENT,
                    "Unknown key type: " + keyType);
        }
    }

    private static String encodeBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static byte[] decodeBase64(String value, String field) {
        if (value == null || value.isEmpty()) {
            throw new HsmException(HsmErrorCode.INVALID_ARGUMENT, field + " is required");
        }
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new HsmException(HsmErrorCode.INVALID_ARGUMENT,
                    field + " must be Base64 encoded");
        }
    }
}
