package com.clarium.clarium_sso.constant;

public class ApplicationConstants {

    //INFO MESSAGES
    public static final String SIGNUP_SUCCESSFUL = "The Employee Data has been signed up Successfully";
    public static final String LOGIN_SUCCESSFUL = "Login successful";
    public static final String PROTECTED_ROUTE_ACCESS = "You accessed a protected route!";
    public static final String TEST_ENDPOINT_SUCCESS = "Test endpoint works!";
    public static final String STATUS_VERIFIED = "VERIFIED";
    public static final String RESPONSE_PASSWORD_RESET_SENT = "Password reset OTP sent to your email";
    public static final String RESPONSE_OTP_VERIFIED = "OTP verified successfully";
    public static final String REGISTRATION_SUCCESSFUL = "Registration successful!";
    public static final String PASSWORD_RESET_SUCCESS = "Password reset successful";
    public static final String OTP_SENT = "OTP sent to your email. Please verify to complete registration.";
    public static final String SESSION_EXPIRED = "Session expired";


    //ERROR MESSAGES
    public static final String ACCESS_DENIED = "Access Denied";
    public static final String INVALID_EMAIL_OR_PASSWORD = "Invalid email or password";
    public static final String INTERNAL_SERVER_ERROR_MESSAGE = "Internal server error - ";
    public static final String FAILED = "FAILED";
    public static final String AUTHENTICATION_REQUIRED  = "Authentication required";

    public static final String ERROR_OTP_NOT_FOUND = "OTP expired or not found";
    public static final String ERROR_OTP_EXPIRED = "OTP expired";
    public static final String ERROR_INVALID_OTP = "Invalid OTP";
    public static final String ERROR_VERIFY_OTP_FIRST = "Please verify OTP first";


    public static final String USER_NOT_FOUND_WITH_EMAIL_ID = "User not found with this email id";
    public static final String USER_NOT_FOUND_WITH_USERNAME = "User not found with this username: ";
    public static final String NO_DESIGNATION_ID_FOR_EMPLOYEE_ID = "No Designation Id found with this Employee id: ";
    public static final String NO_DESIGNATION_FOUND_WITH_ID = "No Designation found with this designation Id :";
    public static final String NO_EMPLOYEE_FOUND_WITH_EMAIL = "No employee found with email: ";
    public static final String EMAIL_ALREADY_REGISTERED = "Email already registered. Please log in.";
    public static final String USERNAME_ALREADY_TAKEN = "Username already taken. Please choose another.";
    public static final String EMAIL_NOT_REGISTERED_AS_EMPLOYEE = "Email not registered as employee. Signup denied";

    //ROLE CONSTANTS
    public static final String ROLE_USER = "ROLE_USER";


    //JWT CONSTANTS
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer";
    public static final String JWT_TOKEN_TYPE = "jwt";

    //OTP CONSTANTS
    public static final int OTP_EXPIRY_MINUTES = 10;
    public static final String SUBJECT_PASSWORD_RESET = "Your Password Reset OTP";
    public static final String SUBJECT_REGISTRATION = "Your Registration OTP";
    public static final String MESSAGE_PASSWORD_RESET_PREFIX = "Your OTP for Password reset is: ";
    public static final String MESSAGE_VALIDITY_SUFFIX = "\nValid for " + OTP_EXPIRY_MINUTES + " minutes.";
    public static final String MESSAGE_REGISTRATION_PREFIX = "Your OTP for registration is: ";

    //IMAGE CONSTANTS
    public static final String JPG= "jpg";


    //OAUTH ATTRIBUTE KEYS
    public static final String OAUTH_ATTR_SUB = "sub";
    public static final String OAUTH_ATTR_NAME = "name";
    public static final String OAUTH_ATTR_EMAIL = "email";
    public static final String OAUTH_ATTR_GIVEN_NAME = "given_name";
    public static final String OAUTH_ATTR_FAMILY_NAME = "family_name";
    public static final String OAUTH_ATTR_PICTURE = "picture";
    public static final String AUTHENTICATION_FAILED = "Authentication Failed";

    //COOKIES
    public static final String JSESSION_ID= "JSESSIONID";
    public static final String XSRF_TOKEN= "XSRF-TOKEN";

    //CAPTCHA CONSTANTS
    public static final String CAPTCHA_ATTRIBUTE= "captcha";
    public static final String CAPTCHA_EXPIRED = "CAPTCHA has expired. Please generate new CAPTCHA.";
    public static final String CAPTCHA_NOT_FOUND= "CAPTCHA not found. Please generate new CAPTCHA.";
    public static final String CAPTCHA_INVALID = "INVALID_CAPTCHA";
    public static final String CAPTCHA_TIMESTAMP = "captcha_timestamp";
    public static final long CAPTCHA_EXPIRY_TIME = 5 * 60 * 1000;










}