package com.clarium.clarium_sso.exception;

import org.springframework.http.HttpStatus;

import static com.clarium.clarium_sso.constant.ApplicationConstants.FAILED;
import static com.clarium.clarium_sso.constant.ExceptionConstants.CODE_INVALID_CREDENTIALS;
import static com.clarium.clarium_sso.constant.ExceptionConstants.MODULE_AUTHENTICATION;

public class InvalidCredentialsException extends BaseException {


    public InvalidCredentialsException(String message) {
        super(HttpStatus.UNAUTHORIZED, CODE_INVALID_CREDENTIALS, MODULE_AUTHENTICATION, message, FAILED);
    }

}