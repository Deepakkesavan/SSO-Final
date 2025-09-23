package com.clarium.clarium_sso.security;

import com.clarium.clarium_sso.service.CustomUserDetails;
import com.clarium.clarium_sso.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static com.clarium.clarium_sso.constant.ApplicationConstants.JWT_TOKEN_TYPE;
import static com.clarium.clarium_sso.constant.ApplicationConstants.ROLE_USER;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.REFRESH_TOKEN;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String token = extractToken(request);

        if (token != null && !token.isEmpty()) {
            try {
                if (jwtUtil.validateToken(token)) {
                    Claims claims = jwtUtil.extractAllClaims(token);
                    setAuthentication(claims, request);
                } else if (jwtUtil.isTokenExpired(token)) {
                    // Try using refresh token if JWT expired
                    handleRefreshToken(request, response);
                } else {
                    clearTokens(response);
                }
            } catch (ExpiredJwtException e) {
                handleRefreshToken(request, response);
            } catch (Exception e) {
                clearTokens(response);
            }
        }

        filterChain.doFilter(request, response);
    }

    // Extract JWT from header or cookie
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

    // Set authentication in SecurityContext
    private void setAuthentication(Claims claims, HttpServletRequest request) {
        String email = claims.getSubject();
        int empId = claims.get("empId", Integer.class);
        String designation = claims.get("designation", String.class);

        CustomUserDetails userDetails = new CustomUserDetails(email, empId, designation);

        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        boolean hasOAuth2Auth = currentAuth instanceof OAuth2AuthenticationToken;

        if (!hasOAuth2Auth) {
            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            List.of(new SimpleGrantedAuthority(ROLE_USER))
                    );
            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(auth);
        }
    }

    // Handle refresh token logic
    private void handleRefreshToken(HttpServletRequest request, HttpServletResponse response) {
        Optional<Cookie> refreshCookie = Optional.empty();
        if (request.getCookies() != null) {
            refreshCookie = Optional.ofNullable(
                    java.util.Arrays.stream(request.getCookies())
                            .filter(c -> REFRESH_TOKEN.equals(c.getName()))
                            .findFirst()
                            .orElse(null)
            );
        }

        if (refreshCookie.isPresent()) {
            try {
                String refreshToken = refreshCookie.get().getValue();
                String email = jwtUtil.getEmailFromRefreshToken(refreshToken);

                // TODO: Optionally load empId and designation from DB
                int empId = 0; // replace with actual retrieval
                String designation = "User"; // replace with actual retrieval

                String newAccessToken = jwtUtil.generateToken(email, empId, designation);
                Cookie jwtCookie = jwtUtil.createJwtCookie(newAccessToken);
                response.addCookie(jwtCookie);

                Claims claims = jwtUtil.extractAllClaims(newAccessToken);
                setAuthentication(claims, request);

            } catch (Exception e) {
                clearTokens(response);
            }
        } else {
            clearTokens(response);
        }
    }

    // Clear JWT and refresh token cookies
    private void clearTokens(HttpServletResponse response) {
        Cookie clearJwt = new Cookie(JWT_TOKEN_TYPE, "");
        clearJwt.setPath("/");
        clearJwt.setMaxAge(0);

        Cookie clearRefresh = new Cookie(REFRESH_TOKEN, "");
        clearRefresh.setPath("/");
        clearRefresh.setMaxAge(0);

        response.addCookie(clearJwt);
        response.addCookie(clearRefresh);

        SecurityContextHolder.clearContext();
    }
}
