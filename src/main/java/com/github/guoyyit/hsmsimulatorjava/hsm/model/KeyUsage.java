package com.github.guoyyit.hsmsimulatorjava.hsm.model;

/**
 * Allowed uses of a key object; enforced before every cryptographic operation.
 */
public enum KeyUsage {
    SIGN,
    VERIFY,
    ENCRYPT,
    DECRYPT,
    WRAP,
    UNWRAP
}
