package com.clarium.clarium_sso.security;

import com.clarium.clarium_sso.service.CustomUserDetails;
import com.clarium.clarium_sso.util.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.clarium.clarium_sso.constant.ApplicationConstants.*;
import static com.clarium.clarium_sso.constant.ExceptionConstants.*;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // ✅ 1. If already authenticated (OAuth2 / Session), skip JWT
        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
        if (existingAuth != null && existingAuth.isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        // ✅ 2. Extract JWT
        String token = extractToken(request);

        if (token == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // ✅ 3. Validate and set authentication
            if (jwtUtil.validateToken(token)) {
                Claims claims = jwtUtil.extractAllClaims(token);
                setAuthentication(claims, request);
            }

            filterChain.doFilter(request, response);

        } catch (ExpiredJwtException ex) {
            handleJwtException(response, JWT_TOKEN_EXPIRED, CODE_JWT_EXPIRED, HttpServletResponse.SC_UNAUTHORIZED);
        } catch (MalformedJwtException ex) {
            handleJwtException(response, JWT_TOKEN_MALFORMED, CODE_JWT_MALFORMED, HttpServletResponse.SC_UNAUTHORIZED);
        } catch (SignatureException ex) {
            handleJwtException(response, JWT_SIGNATURE_INVALID, CODE_JWT_SIGNATURE_INVALID, HttpServletResponse.SC_UNAUTHORIZED);
        } catch (io.jsonwebtoken.JwtException ex) {
            handleJwtException(response, JWT_TOKEN_INVALID + ": " + ex.getMessage(), CODE_JWT_INVALID, HttpServletResponse.SC_UNAUTHORIZED);
        } catch (Exception ex) {
            handleJwtException(response, "JWT processing error: " + ex.getMessage(), CODE_JWT_INVALID, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Skip JWT filter for auth-related endpoints
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/api/auth/")
                || path.startsWith("/login/")
                || path.startsWith("/oauth2/")
                || path.startsWith("/custom-login/");
    }

    /**
     * Extract JWT from Authorization header or Cookie
     */
    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }

        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (JWT_TOKEN_TYPE.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    /**
     * Set authentication into SecurityContext
     */
    private void setAuthentication(Claims claims, HttpServletRequest request) {
        String email = claims.getSubject();
        Integer empId = claims.get("empId", Integer.class);
        String designation = claims.get("designation", String.class);

        CustomUserDetails userDetails = new CustomUserDetails(email, empId, designation);

        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();

        if (currentAuth == null || !currentAuth.isAuthenticated()) {
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    List.of(new SimpleGrantedAuthority(ROLE_USER))
            );

            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
    }

    /**
     * Handle JWT exceptions and send JSON error response
     */
    private void handleJwtException(HttpServletResponse response, String errorMessage,
                                    String errorCode, int statusCode) throws IOException {
        response.setStatus(statusCode);
        response.setContentType(APPLICATION_CONSTANTS);
        response.setCharacterEncoding(UTF_8);

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("id", (int) (Math.random() * 5000) + 5000);
        errorResponse.put("error", errorMessage);
        errorResponse.put("errorCode", errorCode);
        errorResponse.put("errorModule", MODULE_SECURITY);
        errorResponse.put("status", FAILED);
        errorResponse.put("timestamp", System.currentTimeMillis());

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        response.getWriter().flush();
    }
}