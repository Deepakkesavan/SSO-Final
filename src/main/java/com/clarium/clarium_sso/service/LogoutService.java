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
            "jwt", "JSESSIONID", "XSRF-TOKEN", "remember-me", "SESSION"
    );

    public void performCompleteLogout(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Get current authentication before clearing
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null) {
                System.out.println("Current authentication type: " + authentication.getClass().getSimpleName());
                System.out.println("Is OAuth2: " + (authentication instanceof OAuth2AuthenticationToken));
                System.out.println("Principal type: " + authentication.getPrincipal().getClass().getSimpleName());
            }

            // 1. Handle OAuth2 logout if applicable
            if (authentication instanceof OAuth2AuthenticationToken) {
                System.out.println("Handling OAuth2 logout...");
                SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
                logoutHandler.setInvalidateHttpSession(true);
                logoutHandler.setClearAuthentication(true);
                logoutHandler.logout(request, response, authentication);
            }

            // 2. Clear all authentication cookies
            clearAllCookies(request, response);

            // 3. Invalidate HTTP session completely
            invalidateSession(request);

            // 4. Clear Spring Security Context
            clearSecurityContext();

            // 5. Clear any cached authentication
            clearAuthenticationCache(request);

            // 6. Set security headers to prevent caching
            setSecurityHeaders(response);


        } catch (Exception e) {
            System.err.println("Error during logout: " + e.getMessage());
            e.printStackTrace();

            // Even on error, try basic cleanup
            try {
                clearAllCookies(request, response);
                invalidateSession(request);
                clearSecurityContext();
            } catch (Exception cleanupError) {
                System.err.println("Error during cleanup: " + cleanupError.getMessage());
            }
        }
    }

    private void clearAllCookies(HttpServletRequest request, HttpServletResponse response) {
        System.out.println("Clearing all cookies...");

        // Clear known cookies
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
    }

    private void clearCookie(HttpServletResponse response, String cookieName) {
        // Clear with root path
        Cookie cookie1 = new Cookie(cookieName, "");
        cookie1.setPath("/");
        cookie1.setMaxAge(0);
        cookie1.setHttpOnly(true);
        response.addCookie(cookie1);

        // Clear with application context path
        Cookie cookie2 = new Cookie(cookieName, "");
        cookie2.setPath("/");
        cookie2.setMaxAge(0);
        cookie2.setHttpOnly(false); // For XSRF-TOKEN
        response.addCookie(cookie2);

        // Clear with domain
        Cookie cookie3 = new Cookie(cookieName, "");
        cookie3.setPath("/");
        cookie3.setMaxAge(0);
        cookie3.setDomain("localhost");
        response.addCookie(cookie3);

        // Set explicit expiry headers
        response.addHeader("Set-Cookie",
                cookieName + "=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly");
        response.addHeader("Set-Cookie",
                cookieName + "=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax");
    }

    private void invalidateSession(HttpServletRequest request) {
        System.out.println("Invalidating HTTP session...");

        try {
            HttpSession session = request.getSession(false);
            if (session != null) {
                System.out.println("Session ID before invalidation: " + session.getId());

                // Clear all session attributes
                session.getAttributeNames().asIterator().forEachRemaining(session::removeAttribute);

                // Invalidate the session
                session.invalidate();
                System.out.println("Session invalidated successfully");
            } else {
                System.out.println("No session to invalidate");
            }
        } catch (Exception e) {
            System.err.println("Error invalidating session: " + e.getMessage());
        }
    }

    private void clearSecurityContext() {
        System.out.println("Clearing Spring Security context...");

        try {
            SecurityContext context = SecurityContextHolder.getContext();
            if (context != null) {
                context.setAuthentication(null);
            }
            SecurityContextHolder.clearContext();

            // Also clear from thread local
            SecurityContextHolder.getContextHolderStrategy().clearContext();
            System.out.println("Security context cleared");
        } catch (Exception e) {
            System.err.println("Error clearing security context: " + e.getMessage());
        }
    }

    private void clearAuthenticationCache(HttpServletRequest request) {
        System.out.println("Clearing authentication cache...");

        try {
            // Remove any Spring Security related attributes
            request.removeAttribute("SPRING_SECURITY_CONTEXT");
            request.removeAttribute("SPRING_SECURITY_LAST_EXCEPTION");

            // Clear from request scope
            if (request.getSession(false) != null) {
                request.getSession().removeAttribute("SPRING_SECURITY_CONTEXT");
                request.getSession().removeAttribute("SPRING_SECURITY_SAVED_REQUEST");
            }
        } catch (Exception e) {
            System.err.println("Error clearing authentication cache: " + e.getMessage());
        }
    }

    private void setSecurityHeaders(HttpServletResponse response) {
        // Prevent caching
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate, private");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "0");

        // Clear any authentication headers
        response.setHeader("Authorization", "");
        response.setHeader("WWW-Authenticate", "");
    }
}