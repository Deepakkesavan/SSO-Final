package com.clarium.clarium_sso.exception;

import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.http.HttpStatus;

import java.io.Serial;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.concurrent.ThreadLocalRandom;

@EqualsAndHashCode(callSuper = true)
@Data
public class BaseException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    private int id = ThreadLocalRandom.current().nextInt(5000, 10000);
    private HttpStatus httpStatus;
    private String status;
    private String errorCode;
    private String errorModule;
    private String exceptionMessage;
    private String timeStamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss")
            .format(new Timestamp(System.currentTimeMillis()));

    // Constructor with HttpStatus, errorCode, errorModule, message, and status
    public BaseException(HttpStatus httpStatus, String errorCode, String errorModule,
                         String exceptionMessage, String status) {
        super(exceptionMessage);
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
        this.errorModule = errorModule;
        this.exceptionMessage = exceptionMessage;
        this.status = status;
    }


}