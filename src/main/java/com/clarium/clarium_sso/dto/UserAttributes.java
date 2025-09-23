package com.clarium.clarium_sso.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserAttributes {
    private String givenName;
    private String familyName;
    private String name;
    private String id;
    private String email;
    private String picture;


}
