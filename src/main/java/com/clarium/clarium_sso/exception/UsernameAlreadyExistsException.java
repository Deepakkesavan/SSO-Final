package com.clarium.clarium_sso.exception;

import org.springframework.http.HttpStatus;

import static com.clarium.clarium_sso.constant.ApplicationConstants.FAILED;
import static com.clarium.clarium_sso.constant.ExceptionConstants.CODE_USERNAME_EXISTS;
import static com.clarium.clarium_sso.constant.ExceptionConstants.MODULE_USER_REGISTRATION;

public class UsernameAlreadyExistsException extends BaseException {

    public UsernameAlreadyExistsException(String message) {
        super(HttpStatus.BAD_REQUEST, CODE_USERNAME_EXISTS, MODULE_USER_REGISTRATION, message, FAILED);
    }

}