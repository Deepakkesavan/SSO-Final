package com.clarium.clarium_sso.dto;

public record LoginResponse(
        String message,
        int empId,
        String designation
) {}
