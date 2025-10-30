package com.clarium.clarium_sso.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    private Key key;

    private final long ACCESS_TOKEN_EXPIRATION = 1000 * 60; // 15 minutes
    private final long REFRESH_TOKEN_EXPIRATION = 1000L * 60 * 60 * 24 * 7; // 7 days

    public long getAccessTokenExpiration(){
        return this.ACCESS_TOKEN_EXPIRATION;
    }

    public long getRefreshTokenExpiration(){
        return this.REFRESH_TOKEN_EXPIRATION;
    }

    @PostConstruct
    public void init() {
        if (secret == null || secret.isEmpty()) {
            throw new IllegalStateException("JWT secret is not set in application.properties!");
        }
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    // -------------------- Generate Access JWT --------------------
    public String generateToken(String email, int empId, String designation) {
        checkKeyInitialized();
        return Jwts.builder()
                .setSubject(email)
                .claim("empId", empId)
                .claim("designation", designation)
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION))
                .signWith(key)
                .compact();
    }

    // -------------------- Generate Refresh JWT --------------------
    public String generateRefreshToken(String email, int empId, String designation) {
        checkKeyInitialized();
        return Jwts.builder()
                .setSubject(email)
                .claim("empId", empId)
                .claim("designation", designation)
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION))
                .signWith(key)
                .compact();
    }

    // -------------------- Extract Claims --------------------
    public Claims extractAllClaims(String token) {
        checkKeyInitialized();
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    // -------------------- Validate token --------------------
    public boolean validateToken(String token) {
        checkKeyInitialized();
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            System.out.println("Token expired: " + e.getMessage());
        } catch (MalformedJwtException e) {
            System.out.println("Malformed token: " + e.getMessage());
        } catch (JwtException e) {
            System.out.println("JWT validation error: " + e.getMessage());
        }
        return false;
    }

    public boolean isTokenExpired(String token) throws ExpiredJwtException, JwtException {
        return extractAllClaims(token).getExpiration().before(new Date());
    }

    // -------------------- Create JWT Cookies --------------------
    public Cookie createJwtCookie(String token, boolean secure) {
        checkKeyInitialized();
        Cookie cookie = new Cookie("JWT", token);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure); // true in production
        cookie.setPath("/");
        cookie.setMaxAge((int) (ACCESS_TOKEN_EXPIRATION / 1000));
        cookie.setAttribute("SameSite", "None"); // Cross-site if needed
        return cookie;
    }

    public Cookie createRefreshCookie(String refreshToken, boolean secure) {
        checkKeyInitialized();
        Cookie cookie = new Cookie("REFRESH_TOKEN", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath("/");
        cookie.setMaxAge((int) (REFRESH_TOKEN_EXPIRATION / 1000));
        cookie.setAttribute("SameSite", "None");
        return cookie;
    }

    public String getEmailFromRefreshToken(String token) {
        return extractAllClaims(token).getSubject();
    }

    // -------------------- Utility --------------------
    private void checkKeyInitialized() {
        if (key == null) {
            throw new IllegalStateException("JWT signing key is not initialized. Make sure @PostConstruct ran and secret is set.");
        }
    }
}
