package com.clarium.clarium_sso.exception;

import org.springframework.http.HttpStatus;

import static com.clarium.clarium_sso.constant.ExceptionConstants.*;

public class EmailAlreadyExistsException extends BaseException {
    public EmailAlreadyExistsException(String message) {
        super(HttpStatus.BAD_REQUEST, CODE_EMAIL_EXISTS, MODULE_USER_REGISTRATION, message, "FAILED");
    }
}