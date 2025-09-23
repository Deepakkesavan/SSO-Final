package com.clarium.clarium_sso.dto;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ErrorResponse {
    private int id;
    private String error;
    private String errorCode;
    private String errorModule;
    private String status;
    private String timestamp;
}

