package com.clarium.clarium_sso.service;

import com.clarium.clarium_sso.dto.RedirectUrlResponse;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;

@Service
public class RedirectUrlService {
    private final WebClient webClient;
    public RedirectUrlService(WebClient.Builder builder) {
        this.webClient = builder.baseUrl("https://workspace-dev.clarium.tech/").build();
    }
    public String getSuccessUrl(String Host){
        List<RedirectUrlResponse> responses = webClient.post().uri("/config/api/ClariumConfiguration/sso-redirect").retrieve().bodyToFlux(RedirectUrlResponse.class).collectList().block();
        if (responses.isEmpty() || responses == null) {
            throw new RuntimeException("Empty Direct Response");
        }
        String MatchedURL = responses.stream().filter(r -> r.getHost().equals(Host)).map(RedirectUrlResponse::getRedirectUrl).findFirst().orElse(null);
        System.out.println("Host: " + Host + " MatchedUrl: " + MatchedURL);
        return responses.stream()
                .filter(r-> r.getHost().equals(Host))
                .map(RedirectUrlResponse::getRedirectUrl)
                .findFirst()
                .orElseThrow(() -> new RuntimeException("No Redirect URI found for Host: " + Host));
    }
}
