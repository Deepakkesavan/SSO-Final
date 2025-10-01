package com.clarium.clarium_sso.model;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDate;
import java.util.UUID;

@Entity
@Table(name = "SsoUsers")
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(name = "exit_date")
    private LocalDate exitDate;  // When employee left - for 90-day tracking

    @Column(name = "first_time_login")
    private Boolean firstTimeLogin = true;

}
