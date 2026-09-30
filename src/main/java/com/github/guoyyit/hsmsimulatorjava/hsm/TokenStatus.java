package com.github.guoyyit.hsmsimulatorjava.hsm;

public record TokenStatus(
        boolean initialized,
        boolean locked,
        boolean soLocked,
        boolean userLocked,
        int soFailures,
        int userFailures,
        int maxAttempts,
        int keyCount,
        int sessionCount
) {
}
