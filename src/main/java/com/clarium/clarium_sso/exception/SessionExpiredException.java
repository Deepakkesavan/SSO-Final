package com.clarium.clarium_sso.exception;

import org.springframework.http.HttpStatus;

import static com.clarium.clarium_sso.constant.ApplicationConstants.FAILED;
import static com.clarium.clarium_sso.constant.ExceptionConstants.*;

public class SessionExpiredException extends BaseException{

    public SessionExpiredException(String message) {
        super(HttpStatus.UNAUTHORIZED, CODE_SESSION_EXPIRED, MODULE_SECURITY, message, FAILED);
    }
}
