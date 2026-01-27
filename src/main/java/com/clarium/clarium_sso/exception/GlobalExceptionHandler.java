package com.clarium.clarium_sso.exception;

import com.clarium.clarium_sso.dto.ErrorResponse;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.concurrent.ThreadLocalRandom;

import static com.clarium.clarium_sso.constant.ApplicationConstants.*;
import static com.clarium.clarium_sso.constant.ExceptionConstants.*;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // ========== BASE EXCEPTION HANDLER ==========
    @ExceptionHandler(BaseException.class)
    public ResponseEntity<ErrorResponse> handleBaseException(BaseException ex) {
        return buildErrorResponse(ex);
    }

    // ========== JWT EXCEPTIONS ==========

    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<ErrorResponse> handleExpiredJwtException(ExpiredJwtException ex) {
        ErrorResponse response = ErrorResponse.builder()
                .id(ThreadLocalRandom.current().nextInt(5000, 10000))
                .error(JWT_TOKEN_EXPIRED)
                .errorCode(CODE_JWT_EXPIRED)
                .errorModule(MODULE_SECURITY)
                .status(FAILED)
                .timestamp(Instant.now().toString())
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(MalformedJwtException.class)
    public ResponseEntity<ErrorResponse> handleMalformedJwtException(MalformedJwtException ex) {
        ErrorResponse response = ErrorResponse.builder()
                .id(ThreadLocalRandom.current().nextInt(5000, 10000))
                .error(JWT_TOKEN_MALFORMED)
                .errorCode(CODE_JWT_MALFORMED)
                .errorModule(MODULE_SECURITY)
                .status(FAILED)
                .timestamp(Instant.now().toString())
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(SignatureException.class)
    public ResponseEntity<ErrorResponse> handleSignatureException(SignatureException ex) {
        ErrorResponse response = ErrorResponse.builder()
                .id(ThreadLocalRandom.current().nextInt(5000, 10000))
                .error(JWT_SIGNATURE_INVALID)
                .errorCode(CODE_JWT_SIGNATURE_INVALID)
                .errorModule(MODULE_SECURITY)
                .status(FAILED)
                .timestamp(Instant.now().toString())
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(io.jsonwebtoken.JwtException.class)
    public ResponseEntity<ErrorResponse> handleGenericJwtException(io.jsonwebtoken.JwtException ex) {
        ErrorResponse response = ErrorResponse.builder()
                .id(ThreadLocalRandom.current().nextInt(5000, 10000))
                .error(JWT_TOKEN_INVALID + ": " + ex.getMessage())
                .errorCode(CODE_JWT_INVALID)
                .errorModule(MODULE_SECURITY)
                .status(FAILED)
                .timestamp(Instant.now().toString())
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    // ========== OAUTH2 EXCEPTIONS ==========

    @ExceptionHandler(OAuth2AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleOAuth2AuthenticationException(OAuth2AuthenticationException ex) {
        ErrorResponse response = ErrorResponse.builder()
                .id(ThreadLocalRandom.current().nextInt(5000, 10000))
                .error(OAUTH2_AUTHENTICATION_FAILED + ": " + ex.getError().getDescription())
                .errorCode(CODE_OAUTH2_FAILED)
                .errorModule(MODULE_AUTHENTICATION)
                .status(FAILED)
                .timestamp(Instant.now().toString())
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(OAuth2AuthorizationException.class)
    public ResponseEntity<ErrorResponse> handleOAuth2AuthorizationException(OAuth2AuthorizationException ex) {
        ErrorResponse response = ErrorResponse.builder()
                .id(ThreadLocalRandom.current().nextInt(5000, 10000))
                .error(OAUTH2_ACCESS_DENIED + ": " + ex.getError().getDescription())
                .errorCode(CODE_OAUTH2_ACCESS_DENIED)
                .errorModule(MODULE_AUTHENTICATION)
                .status(FAILED)
                .timestamp(Instant.now().toString())
                .build();

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    // ========== SPRING SECURITY EXCEPTIONS ==========

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentialsException(BadCredentialsException ex) {
        ErrorResponse response = ErrorResponse.builder()
                .id(ThreadLocalRandom.current().nextInt(5000, 10000))
                .error(INVALID_EMAIL_OR_PASSWORD)
                .errorCode(CODE_INVALID_CREDENTIALS)
                .errorModule(MODULE_AUTHENTICATION)
                .status(FAILED)
                .timestamp(Instant.now().toString())
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationException(AuthenticationException ex) {
        ErrorResponse response = ErrorResponse.builder()
                .id(ThreadLocalRandom.current().nextInt(5000, 10000))
                .error(AUTHENTICATION_REQUIRED + ": " + ex.getMessage())
                .errorCode(CODE_INVALID_CREDENTIALS)
                .errorModule(MODULE_AUTHENTICATION)
                .status(FAILED)
                .timestamp(Instant.now().toString())
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(SessionAuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleSessionAuthenticationException(SessionAuthenticationException ex) {
        ErrorResponse response = ErrorResponse.builder()
                .id(ThreadLocalRandom.current().nextInt(5000, 10000))
                .error(SESSION_EXPIRED + ": " + ex.getMessage())
                .errorCode(CODE_SESSION_EXPIRED)
                .errorModule(MODULE_SECURITY)
                .status(FAILED)
                .timestamp(Instant.now().toString())
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    // ========== GENERIC EXCEPTION HANDLER ==========

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleOtherExceptions(Exception ex) {
        ex.printStackTrace(); // Log for debugging

        ErrorResponse errorResponse = ErrorResponse.builder()
                .id(ThreadLocalRandom.current().nextInt(5000, 10000))
                .error(INTERNAL_SERVER_ERROR_MESSAGE + ex.getMessage())
                .errorCode("INTERNAL_ERROR")
                .errorModule("SYSTEM")
                .status(FAILED)
                .timestamp(Instant.now().toString())
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
    }

    // ========== HELPER METHOD ==========

    private ResponseEntity<ErrorResponse> buildErrorResponse(BaseException ex) {
        ErrorResponse response = ErrorResponse.builder()
                .id(ex.getId())
                .error(ex.getExceptionMessage())
                .errorCode(ex.getErrorCode())
                .errorModule(ex.getErrorModule())
                .status(ex.getStatus())
                .timestamp(ex.getTimeStamp())
                .build();

        return ResponseEntity.status(ex.getHttpStatus()).body(response);
    }
}