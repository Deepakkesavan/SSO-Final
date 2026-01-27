package com.clarium.clarium_sso.constant;

public class ExceptionConstants {

    // Modules
    public static final String MODULE_AUTHENTICATION = "AUTHENTICATION";
    public static final String MODULE_USER_REGISTRATION = "USER_REGISTRATION";
    public static final String MODULE_DATA_ACCESS = "DATA_ACCESS";
    public static final String MODULE_SECURITY = "SECURITY";

    // Codes
    public static final String CODE_EMAIL_EXISTS = "EMAIL_EXISTS";
    public static final String CODE_INVALID_CREDENTIALS = "INVALID_CREDENTIALS";
    public static final String CODE_RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND";
    public static final String CODE_NOT_AN_EMPLOYEE = "NOT_AN_EMPLOYEE";
    public static final String CODE_USERNAME_EXISTS = "USERNAME_EXISTS";
    public static final String CODE_CAPTCHA_EXPIRED = "CAPTCHA_EXPIRED";
    public static final String CODE_SESSION_EXPIRED = "SESSION_EXPIRED";

    // JWT Codes
    public static final String CODE_JWT_INVALID = "JWT_INVALID";
    public static final String CODE_JWT_EXPIRED = "JWT_EXPIRED";
    public static final String CODE_JWT_MALFORMED = "JWT_MALFORMED";
    public static final String CODE_JWT_SIGNATURE_INVALID = "JWT_SIGNATURE_INVALID";

    // OAuth2 Codes
    public static final String CODE_OAUTH2_FAILED = "OAUTH2_FAILED";
    public static final String CODE_OAUTH2_USER_NOT_FOUND = "OAUTH2_USER_NOT_FOUND";
    public static final String CODE_OAUTH2_ACCESS_DENIED = "OAUTH2_ACCESS_DENIED";
}