package com.clarium.clarium_sso.exception;

import org.springframework.http.HttpStatus;

import static com.clarium.clarium_sso.constant.ApplicationConstants.FAILED;
import static com.clarium.clarium_sso.constant.ExceptionConstants.CODE_JWT_INVALID;
import static com.clarium.clarium_sso.constant.ExceptionConstants.MODULE_SECURITY;

public class JwtException extends BaseException {
    public JwtException(String message) {
        super(HttpStatus.UNAUTHORIZED, CODE_JWT_INVALID, MODULE_SECURITY, message, FAILED);
    }
}