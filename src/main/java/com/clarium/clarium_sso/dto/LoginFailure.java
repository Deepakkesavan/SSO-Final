package com.clarium.clarium_sso.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LoginFailure {
    private boolean status;
    private String message;
}
