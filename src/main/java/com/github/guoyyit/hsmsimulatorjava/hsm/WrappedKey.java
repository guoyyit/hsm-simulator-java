package com.github.guoyyit.hsmsimulatorjava.hsm;

public record WrappedKey(
        int version,
        String alg,
        String wrappingKeyId,
        byte[] iv,
        byte[] encryptedCek,
        byte[] ciphertext
) {
}
