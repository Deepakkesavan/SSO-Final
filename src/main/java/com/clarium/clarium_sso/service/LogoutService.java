package com.clarium.clarium_sso.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class LogoutService {

    private static final List<String> COOKIES_TO_CLEAR = Arrays.asList(
            "JWT", "JSESSIONID", "XSRF-TOKEN", "REFRESH_TOKEN", "remember-me", "SESSION"
    );

    public void performCompleteLogout(HttpServletRequest request, HttpServletResponse response) {
        try {
            System.out.println("Starting complete logout process...");

            // Get current authentication before clearing
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null) {
                System.out.println("Current authentication type: " + authentication.getClass().getSimpleName());

                // Handle OAuth2 logout if applicable
                if (authentication instanceof OAuth2AuthenticationToken) {
                    System.out.println("Handling OAuth2 logout...");
                    SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
                    logoutHandler.setInvalidateHttpSession(true);
                    logoutHandler.setClearAuthentication(true);
                    logoutHandler.logout(request, response, authentication);
                }
            }

            // 1. Clear Spring Security Context first
            clearSecurityContext();

            // 2. Clear all authentication cookies
            clearAllCookies(request, response);

            // 3. Invalidate HTTP session completely
            invalidateSession(request);

            // 4. Set security headers to prevent caching
            setSecurityHeaders(response);

            System.out.println("Complete logout process finished successfully");

        } catch (Exception e) {
            System.err.println("Error during logout: " + e.getMessage());
            e.printStackTrace();

            // Even on error, try basic cleanup
            try {
                clearSecurityContext();
                clearAllCookies(request, response);
                invalidateSession(request);
                setSecurityHeaders(response);
            } catch (Exception cleanupError) {
                System.err.println("Error during cleanup: " + cleanupError.getMessage());
            }

            throw new RuntimeException("Logout process encountered errors", e);
        }
    }

    private void clearSecurityContext() {
        try {
            SecurityContext context = SecurityContextHolder.getContext();
            if (context != null) {
                context.setAuthentication(null);
            }
            SecurityContextHolder.clearContext();
            SecurityContextHolder.getContextHolderStrategy().clearContext();
            System.out.println("Security context cleared successfully");
        } catch (Exception e) {
            System.err.println("Error clearing security context: " + e.getMessage());
        }
    }

    private void clearAllCookies(HttpServletRequest request, HttpServletResponse response) {
        System.out.println("Clearing authentication cookies...");

        // Clear known authentication cookies
        for (String cookieName : COOKIES_TO_CLEAR) {
            clearCookie(response, cookieName);
        }

        // Clear all existing cookies from request
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                System.out.println("Clearing cookie: " + cookie.getName());
                clearCookie(response, cookie.getName());
            }
        }

        System.out.println("All cookies cleared");
    }

    private void clearCookie(HttpServletResponse response, String cookieName) {
        // Method 1: Standard cookie clearing
        Cookie expiredCookie = new Cookie(cookieName, "");
        expiredCookie.setPath("/");
        expiredCookie.setMaxAge(0);
        expiredCookie.setHttpOnly(true);
        response.addCookie(expiredCookie);

        // Method 2: Additional cookie clearing with domain
        Cookie expiredCookieWithDomain = new Cookie(cookieName, "");
        expiredCookieWithDomain.setPath("/");
        expiredCookieWithDomain.setMaxAge(0);
        expiredCookieWithDomain.setDomain("localhost");
        response.addCookie(expiredCookieWithDomain);

        // Method 3: Set explicit expiry headers
        response.addHeader("Set-Cookie",
                cookieName + "=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax");
    }

    private void invalidateSession(HttpServletRequest request) {
        try {
            HttpSession session = request.getSession(false);
            if (session != null) {
                String sessionId = session.getId();
                System.out.println("Invalidating session: " + sessionId);

                // Clear all session attributes first
                session.getAttributeNames().asIterator()
                        .forEachRemaining(session::removeAttribute);

                // Invalidate the session
                session.invalidate();
                System.out.println("Session invalidated successfully");
            } else {
                System.out.println("No active session to invalidate");
            }
        } catch (Exception e) {
            System.err.println("Error invalidating session: " + e.getMessage());
        }
    }

    private void setSecurityHeaders(HttpServletResponse response) {
        // Prevent caching of authenticated content
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate, private");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "0");

        // Clear any authentication headers
        response.setHeader("Authorization", "");
        response.setHeader("WWW-Authenticate", "");

        // Additional security headers
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("X-Content-Type-Options", "nosniff");

        System.out.println("Security headers set");
    }
}