package com.github.guoyyit.hsmsimulatorjava.hsm.exception;

import com.github.guoyyit.hsmsimulatorjava.hsm.model.HsmError;

/**
 * Business exception carrying a distinguishable {@link HsmError} code.
 */
public class HsmException extends RuntimeException {

    private final HsmError error;

    public HsmException(HsmError error) {
        super();
        this.error = error;
    }

    public HsmException(HsmError error, String message) {
        super(message);
        this.error = error;
    }

    public HsmError getError() {
        return error;
    }
}
