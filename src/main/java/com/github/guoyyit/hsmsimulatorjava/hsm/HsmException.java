package com.github.guoyyit.hsmsimulatorjava.hsm;

public class HsmException extends RuntimeException {

    private final HsmErrorCode code;

    public HsmException(HsmErrorCode code) {
        super(code.name());
        this.code = code;
    }

    public HsmException(HsmErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public HsmException(HsmErrorCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public HsmErrorCode getCode() {
        return code;
    }
}
