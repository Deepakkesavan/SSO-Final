package com.clarium.clarium_sso.exception;

import org.springframework.http.HttpStatus;

import static com.clarium.clarium_sso.constant.ApplicationConstants.FAILED;
import static com.clarium.clarium_sso.constant.ExceptionConstants.CODE_JWT_EXPIRED;
import static com.clarium.clarium_sso.constant.ExceptionConstants.MODULE_SECURITY;

public class JwtExpiredException extends BaseException {
    public JwtExpiredException(String message) {
        super(HttpStatus.UNAUTHORIZED, CODE_JWT_EXPIRED, MODULE_SECURITY, message, FAILED);
    }
}