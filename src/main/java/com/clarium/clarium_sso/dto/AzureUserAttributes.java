package com.clarium.clarium_sso.dto;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AzureUserAttributes {
    private boolean authenticated;
    private int empId;
    private String designation;
    private UserAttributes userAttributes;


}
