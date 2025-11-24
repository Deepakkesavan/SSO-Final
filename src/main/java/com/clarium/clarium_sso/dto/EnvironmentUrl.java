package com.clarium.clarium_sso.dto;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "environmenturl")
public class EnvironmentUrl {
    private String successurl;
    private String failureurl;

    public EnvironmentUrl() {
    }

    public EnvironmentUrl(String successurl, String failureurl) {
        this.successurl = successurl;
        this.failureurl = failureurl;
    }

    public String getFailureurl() {
        return failureurl;
    }

    public void setFailureurl(String failureurl) {
        this.failureurl = failureurl;
    }

    public String getSuccessurl() {
        return successurl;
    }

    public void setSuccessurl(String successurl) {
        this.successurl = successurl;
    }
}
