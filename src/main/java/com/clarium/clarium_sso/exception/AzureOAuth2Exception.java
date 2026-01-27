package com.clarium.clarium_sso.exception;

import org.springframework.http.HttpStatus;

import static com.clarium.clarium_sso.constant.ApplicationConstants.FAILED;
import static com.clarium.clarium_sso.constant.ExceptionConstants.CODE_OAUTH2_FAILED;
import static com.clarium.clarium_sso.constant.ExceptionConstants.MODULE_AUTHENTICATION;

public class AzureOAuth2Exception extends BaseException {
    public AzureOAuth2Exception(String message) {
        super(HttpStatus.UNAUTHORIZED, CODE_OAUTH2_FAILED, MODULE_AUTHENTICATION, message, FAILED);
    }
}