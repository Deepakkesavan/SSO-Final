package com.clarium.clarium_sso.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties
public class RedirectUrlResponse {


    @JsonProperty("Host")
    private String Host;

    @JsonProperty("RedirectUrl")
    private String RedirectUrl;

    public RedirectUrlResponse() {
    }

    public RedirectUrlResponse(String host, String redirectUrl) {
        Host = host;
        RedirectUrl = redirectUrl;
    }

    public String getHost() {
        return Host;
    }

    public void setHost(String host) {
        Host = host;
    }

    public String getRedirectUrl() {
        return RedirectUrl;
    }

    public void setRedirectUrl(String redirectUrl) {
        RedirectUrl = redirectUrl;
    }
}



