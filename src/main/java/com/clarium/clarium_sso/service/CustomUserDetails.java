package com.clarium.clarium_sso.service;

import org.springframework.stereotype.Component;

public class CustomUserDetails {
    private final  String  email;
    private final int empId;
    private final String designation;

    public CustomUserDetails(String email, int empId, String designation) {
        this.email = email;
        this.empId = empId;
        this.designation = designation;
    }

    // getters
    public String getEmail() { return email; }
    public int getEmpId() { return empId; }
    public String getDesignation() { return designation; }
}

