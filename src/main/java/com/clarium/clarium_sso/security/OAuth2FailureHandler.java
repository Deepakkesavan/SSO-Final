package com.clarium.clarium_sso.security;

import com.clarium.clarium_sso.dto.EnvironmentUrl;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static com.clarium.clarium_sso.constant.ApplicationConstants.*;
import static com.clarium.clarium_sso.constant.ExceptionConstants.*;

@Component
public class OAuth2FailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final EnvironmentUrl environmentUrl;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public OAuth2FailureHandler(EnvironmentUrl environmentUrl) {
        this.environmentUrl = environmentUrl;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception)
            throws IOException, ServletException {

        String errorMessage = OAUTH2_AUTHENTICATION_FAILED;
        String errorCode = CODE_OAUTH2_FAILED;

        // Handle specific OAuth2 exceptions
        if (exception instanceof OAuth2AuthenticationException oauth2Exception) {
            String errorCodeFromOAuth = oauth2Exception.getError().getErrorCode();

            if ("access_denied".equals(errorCodeFromOAuth)) {
                errorMessage = OAUTH2_ACCESS_DENIED;
                errorCode = CODE_OAUTH2_ACCESS_DENIED;
            } else if ("invalid_state".equals(errorCodeFromOAuth)) {
                errorMessage = OAUTH2_INVALID_STATE;
                errorCode = CODE_OAUTH2_FAILED;
            } else {
                errorMessage = OAUTH2_PROVIDER_ERROR + ": " +
                        oauth2Exception.getError().getDescription();
            }
        }

        // Log the error for debugging
        System.err.println("OAuth2 Authentication Failed: " + errorMessage);
        System.err.println("Exception details: " + exception.getMessage());

        // Check if this is an API request (JSON expected)
        String acceptHeader = request.getHeader("Accept");
        boolean isApiRequest = acceptHeader != null &&
                (acceptHeader.contains("application/json") ||
                        request.getRequestURI().startsWith("/api/"));

        if (isApiRequest) {
            // Send JSON error response for API requests
            sendJsonErrorResponse(response, errorMessage, errorCode);
        } else {
            // Redirect to failure URL with error parameters for browser requests
            String redirectUrl = buildFailureRedirectUrl(errorMessage, errorCode);
            response.sendRedirect(redirectUrl);
        }
    }

    /**
     * Send JSON error response for API requests
     */
    private void sendJsonErrorResponse(HttpServletResponse response,
                                       String errorMessage,
                                       String errorCode) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(APPLICATION_CONSTANTS);
        response.setCharacterEncoding(UTF_8);

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("id", (int) (Math.random() * 5000) + 5000);
        errorResponse.put("error", errorMessage);
        errorResponse.put("errorCode", errorCode);
        errorResponse.put("errorModule", MODULE_AUTHENTICATION);
        errorResponse.put("status", FAILED);
        errorResponse.put("timestamp", System.currentTimeMillis());
        errorResponse.put("authenticated", false);

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        response.getWriter().flush();
    }

    /**
     * Build redirect URL with error parameters
     */
    private String buildFailureRedirectUrl(String errorMessage, String errorCode) {
        String baseUrl = environmentUrl.getFailureurl();

        // Add error parameters to URL
        String separator = baseUrl.contains("?") ? "&" : "?";

        try {
            String encodedMessage = URLEncoder.encode(errorMessage, StandardCharsets.UTF_8);
            String encodedCode = URLEncoder.encode(errorCode, StandardCharsets.UTF_8);

            return baseUrl + separator +
                    "error=true&" +
                    "errorMessage=" + encodedMessage + "&" +
                    "errorCode=" + encodedCode;
        } catch (Exception e) {
            // Fallback to simple error parameter
            return baseUrl + separator + "error=oauth_failed";
        }
    }
}