package com.clarium.clarium_sso.exception;

import org.springframework.http.HttpStatus;

import static com.clarium.clarium_sso.constant.ApplicationConstants.FAILED;
import static com.clarium.clarium_sso.constant.ExceptionConstants.CODE_NOT_AN_EMPLOYEE;
import static com.clarium.clarium_sso.constant.ExceptionConstants.MODULE_AUTHENTICATION;

public class NotAnEmployeeException extends BaseException {

    public NotAnEmployeeException(String message) {
        super(HttpStatus.FORBIDDEN, CODE_NOT_AN_EMPLOYEE, MODULE_AUTHENTICATION, message, FAILED);
    }

}