package com.github.guoyyit.hsmsimulatorjava.hsm.web;

import com.github.guoyyit.hsmsimulatorjava.hsm.exception.HsmException;
import com.github.guoyyit.hsmsimulatorjava.hsm.model.HsmError;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * Translates HSM failures into distinguishable JSON error responses.
 */
@RestControllerAdvice
public class HsmExceptionHandler {

    @ExceptionHandler(HsmException.class)
    public ResponseEntity<Map<String, Object>> handleHsm(HsmException ex) {
        HttpStatus status = httpStatus(ex.getError());
        return ResponseEntity.status(status).body(Map.of(
                "error", ex.getError().name(),
                "status", status.value(),
                "message", ex.getMessage() == null ? "" : ex.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(Map.of(
                "error", HsmError.INVALID_ARGUMENT.name(),
                "status", HttpStatus.BAD_REQUEST.value(),
                "message", ex.getMessage() == null ? "" : ex.getMessage()));
    }

    private HttpStatus httpStatus(HsmError error) {
        return switch (error) {
            case TOKEN_NOT_INITIALIZED, KEY_NOT_FOUND, SESSION_HANDLE_INVALID -> HttpStatus.NOT_FOUND;
            case TOKEN_LOCKED -> HttpStatus.LOCKED;
            case PIN_INCORRECT, SIGNATURE_INVALID -> HttpStatus.UNAUTHORIZED;
            case PIN_LOCKED, KEY_SENSITIVE, KEY_NOT_EXTRACTABLE, KEY_USAGE_VIOLATION,
                 ROLE_REQUIRED, NOT_LOGGED_IN, LOGIN_REQUIRED, ALREADY_LOGGED_IN -> HttpStatus.FORBIDDEN;
            case TOKEN_ALREADY_INITIALIZED -> HttpStatus.CONFLICT;
            case KEY_DESTROYED, DECRYPT_FAILED -> HttpStatus.GONE;
            case WRAPPING_FAILED, UNWRAPPING_FAILED, INVALID_KEY_TYPE, INVALID_ARGUMENT ->
                    HttpStatus.BAD_REQUEST;
            default -> HttpStatus.INTERNAL_SERVER_ERROR;
        };
    }
}
