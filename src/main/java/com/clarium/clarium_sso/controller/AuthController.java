package com.clarium.clarium_sso.controller;

import com.clarium.clarium_sso.dto.AzureUserAttributes;
import com.clarium.clarium_sso.dto.LoginFailure;
import com.clarium.clarium_sso.dto.UserAttributes;
import com.clarium.clarium_sso.repository.UserRepository;
import com.clarium.clarium_sso.service.AuthService;
import com.clarium.clarium_sso.service.CustomUserDetails;
import com.clarium.clarium_sso.service.LogoutService;
import com.clarium.clarium_sso.service.UserService;
import com.clarium.clarium_sso.util.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final UserService userService;
    private final LogoutService logoutService;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    public AuthController(AuthService authService,
                          LogoutService logoutService,
                          JwtUtil jwtUtil,
                          UserRepository userRepository,
                          UserService userService) {
        this.authService = authService;
        this.logoutService = logoutService;
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
        this.userService = userService;
    }

    // -------------------- Auth Status --------------------
    @GetMapping("/auth-status")
    public ResponseEntity<Map<String, Object>> authStatus() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean isAuthenticated = auth != null && auth.isAuthenticated() &&
                !(auth instanceof AnonymousAuthenticationToken);

        return ResponseEntity.ok(Map.of("authenticated", isAuthenticated));
    }

    // -------------------- User Profile --------------------
    @GetMapping("/user-profile")
    public ResponseEntity<UserAttributes> getUserProfile(HttpServletResponse response) {
        AzureUserAttributes azureUser = authService.getCurrentUser(response);
        if (!azureUser.isAuthenticated()) return ResponseEntity.ok(null);
        return ResponseEntity.ok(azureUser.getUserAttributes());
    }

    // -------------------- Get User Attributes --------------------
    @GetMapping("/user-attributes")
    public ResponseEntity<?> getUserAttributes(HttpServletResponse response) {
        return ResponseEntity.ok(authService.getUser(response));
    }

    // -------------------- Validate JWT / OAuth --------------------
    @GetMapping("validate")
    public ResponseEntity<?> validateToken() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // Check if authentication exists and is valid
        if (auth != null && auth.isAuthenticated() && auth.getPrincipal() instanceof CustomUserDetails userDetails) {

//            "user", new AzureUserAttributes(false, 0, "Unknown", null)
            // Build AzureUserAttributes response
            AzureUserAttributes azureUser = new AzureUserAttributes(
                    true,
                    userDetails.getEmpId(),
                    userDetails.getDesignation(),
                    null
            )
;
            return ResponseEntity.ok(Map.of(
                    "valid", true,
                    "user", azureUser
            ));
        }

        // If no valid authentication, return 401
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "valid", false,
                "user", new AzureUserAttributes(false, 0, "Unknown", null)
        ));
    }
    // -------------------- Refresh Token --------------------
    @PostMapping("/refresh-token")
    public ResponseEntity<Map<String, Object>> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = Arrays.stream(request.getCookies() != null ? request.getCookies() : new Cookie[0])
                .filter(c -> "REFRESH_TOKEN".equals(c.getName()))
                .findFirst()
                .map(Cookie::getValue)
                .orElse(null);

        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Missing refresh token"));
        }

        String email = authService.getEmailFromRefreshToken(refreshToken);
        AzureUserAttributes user = authService.getUserByEmail(email);

        // Generate new JWT with empId and designation
        String newJwt = jwtUtil.generateToken(email, user.getEmpId(), user.getDesignation());
        response.addCookie(jwtUtil.createJwtCookie(newJwt));

        return ResponseEntity.ok(Map.of(
                "token", newJwt,
                "user", user
        ));
    }

    // -------------------- Logout --------------------
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            logoutService.performCompleteLogout(request, response);
            return ResponseEntity.ok(Map.of(
                    "message", "Complete logout successful",
                    "timestamp", System.currentTimeMillis(),
                    "status", "SUCCESS"
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "error", "Logout failed",
                    "message", e.getMessage(),
                    "status", "PARTIAL_SUCCESS"
            ));
        }
    }

    // -------------------- Login Failure --------------------
    @GetMapping("/failure")
    public ResponseEntity<LoginFailure> loginFailure() {
        return ResponseEntity.ok(authService.loginFailure());
    }

    // -------------------- Helper Methods --------------------
        private String extractJwt(HttpServletRequest request) {
            System.out.println("Hi from extract jwt method");
            String header = request.getHeader("Authorization");
            if (header != null && header.startsWith("Bearer ")){
                System.out.println(header.substring(7));
                return header.substring(7);
            }

            if (request.getCookies() != null) {
                for (Cookie cookie : request.getCookies()) {
                    if ("JWT".equals(cookie.getName())){
                        System.out.println(cookie.getValue());
                        return cookie.getValue();
                    }
                }
            }
            return null;
        }

}
