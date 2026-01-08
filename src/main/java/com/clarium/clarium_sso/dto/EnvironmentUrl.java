package com.clarium.clarium_sso.dto;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@Data
@ConfigurationProperties(prefix = "environmenturl")
public class EnvironmentUrl {
    private String successurl;
    private String failureurl;
}
