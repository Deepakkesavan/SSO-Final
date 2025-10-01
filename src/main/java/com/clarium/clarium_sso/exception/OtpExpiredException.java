package com.clarium.clarium_sso.exception;

import org.springframework.http.HttpStatus;

import static com.clarium.clarium_sso.constant.ApplicationConstants.FAILED;
import static com.clarium.clarium_sso.constant.ExceptionConstants.CODE_RESOURCE_NOT_FOUND;
import static com.clarium.clarium_sso.constant.ExceptionConstants.MODULE_DATA_ACCESS;

public class OtpExpiredException extends BaseException{

    public OtpExpiredException(String message) {
        super(HttpStatus.GONE, CODE_RESOURCE_NOT_FOUND, MODULE_DATA_ACCESS, message, FAILED);
    }

}
