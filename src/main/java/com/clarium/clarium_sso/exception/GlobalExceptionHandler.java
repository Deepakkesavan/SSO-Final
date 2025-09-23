package com.clarium.clarium_sso.exception;

import com.clarium.clarium_sso.dto.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import static com.clarium.clarium_sso.constant.ApplicationConstants.*;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BaseException.class)
    public ResponseEntity<ErrorResponse> handleBaseException(BaseException ex) {
        return buildErrorResponse(ex);
    }

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

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleOtherExceptions(Exception ex) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .id(-1)
                .error(INTERNAL_SERVER_ERROR_MESSAGE + ex.getMessage())
                .status(FAILED)
                .timestamp(java.time.Instant.now().toString())
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
    }

}