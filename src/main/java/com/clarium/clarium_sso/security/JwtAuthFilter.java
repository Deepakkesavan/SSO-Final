package com.clarium.clarium_sso.security;

import com.clarium.clarium_sso.service.CustomUserDetails;
import com.clarium.clarium_sso.util.JwtUtil;
import io.jsonwebtoken.Claims;
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
import java.util.List;

import static com.clarium.clarium_sso.constant.ApplicationConstants.JWT_TOKEN_TYPE;
import static com.clarium.clarium_sso.constant.ApplicationConstants.ROLE_USER;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // ✅ 1. If already authenticated (OAuth2 / Session), skip JWT
        Authentication existingAuth =
                SecurityContextHolder.getContext().getAuthentication();

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

        // ✅ 3. Handle expired JWT gracefully
        if (jwtUtil.isTokenExpired(token)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // ✅ 4. Validate and set authentication
        if (jwtUtil.validateToken(token)) {
            Claims claims = jwtUtil.extractAllClaims(token);
            setAuthentication(claims, request);
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Skip JWT filter for auth-related endpoints
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/api/auth/")
                || path.startsWith("/login/")
                || path.startsWith("/oauth2/");
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

        CustomUserDetails userDetails =
                new CustomUserDetails(email, empId, designation);

        Authentication currentAuth =
                SecurityContextHolder.getContext().getAuthentication();

        if (currentAuth == null || !currentAuth.isAuthenticated()) {
            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            List.of(new SimpleGrantedAuthority(ROLE_USER))
                    );

            auth.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
            );

            SecurityContextHolder.getContext().setAuthentication(auth);
        }
    }
}
