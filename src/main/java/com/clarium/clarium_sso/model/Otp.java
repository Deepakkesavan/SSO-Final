package com.clarium.clarium_sso.model;


import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Data
public class Otp {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    private String email;
    private String username;
    private String otpCode;
    private LocalDateTime expiry;
}
