package com.github.guoyyit.hsmsimulatorjava.web;

import com.github.guoyyit.hsmsimulatorjava.hsm.HsmErrorCode;
import com.github.guoyyit.hsmsimulatorjava.hsm.HsmException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class HsmExceptionHandler {

    private static final Map<HsmErrorCode, HttpStatus> STATUS_MAP = Map.ofEntries(
            Map.entry(HsmErrorCode.TOKEN_NOT_INITIALIZED, HttpStatus.BAD_REQUEST),
            Map.entry(HsmErrorCode.TOKEN_ALREADY_INITIALIZED, HttpStatus.CONFLICT),
            Map.entry(HsmErrorCode.TOKEN_LOCKED, HttpStatus.LOCKED),
            Map.entry(HsmErrorCode.INVALID_PIN, HttpStatus.UNAUTHORIZED),
            Map.entry(HsmErrorCode.PIN_LOCKED, HttpStatus.LOCKED),
            Map.entry(HsmErrorCode.SESSION_NOT_FOUND, HttpStatus.NOT_FOUND),
            Map.entry(HsmErrorCode.NOT_LOGGED_IN, HttpStatus.UNAUTHORIZED),
            Map.entry(HsmErrorCode.ACCESS_DENIED, HttpStatus.FORBIDDEN),
            Map.entry(HsmErrorCode.KEY_NOT_FOUND, HttpStatus.NOT_FOUND),
            Map.entry(HsmErrorCode.KEY_DESTROYED, HttpStatus.NOT_FOUND),
            Map.entry(HsmErrorCode.USAGE_NOT_ALLOWED, HttpStatus.FORBIDDEN),
            Map.entry(HsmErrorCode.KEY_NOT_EXTRACTABLE, HttpStatus.FORBIDDEN),
            Map.entry(HsmErrorCode.INVALID_ARGUMENT, HttpStatus.BAD_REQUEST),
            Map.entry(HsmErrorCode.CRYPTO_FAILED, HttpStatus.BAD_REQUEST),
            Map.entry(HsmErrorCode.STORAGE_ERROR, HttpStatus.INTERNAL_SERVER_ERROR),
            Map.entry(HsmErrorCode.UNSUPPORTED_OPERATION, HttpStatus.BAD_REQUEST)
    );

    @ExceptionHandler(HsmException.class)
    public ResponseEntity<Map<String, String>> handleHsm(HsmException ex) {
        HttpStatus status = STATUS_MAP.getOrDefault(ex.getCode(), HttpStatus.INTERNAL_SERVER_ERROR);
        return ResponseEntity.status(status).body(Map.of(
                "code", ex.getCode().name(),
                "message", String.valueOf(ex.getMessage())));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleIllegalArgument(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(Map.of(
                "code", HsmErrorCode.INVALID_ARGUMENT.name(),
                "message", String.valueOf(ex.getMessage())));
    }
}
