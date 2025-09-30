package com.clarium.clarium_sso.controller;

import com.clarium.clarium_sso.dto.ForgotPasswordRequest;
import com.clarium.clarium_sso.dto.LoginRequest;
import com.clarium.clarium_sso.dto.LoginResponse;
import com.clarium.clarium_sso.dto.Response;
import com.clarium.clarium_sso.dto.SignupResponse;
import com.clarium.clarium_sso.model.User;
import com.clarium.clarium_sso.service.LogoutService;
import com.clarium.clarium_sso.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

import static com.clarium.clarium_sso.constant.ApplicationConstants.*;

@RestController
@RequestMapping("/custom-login/auth")
public class UserController {

    private final UserService userService;
    private final LogoutService logoutService;

    public UserController(UserService userService, LogoutService logoutService) {
        this.userService = userService;
        this.logoutService = logoutService;
    }

    @PostMapping("/signup")
    public ResponseEntity<SignupResponse> register(@RequestBody User user) {
        User savedUser = userService.register(user);
        SignupResponse signupResponse = new SignupResponse(SIGNUP_SUCCESSFUL, savedUser.getEmail());
        return ResponseEntity.status(HttpStatus.CREATED).body(signupResponse);
    }

    @PostMapping("/signin")
    public ResponseEntity<?> login(@RequestBody LoginRequest req, HttpServletResponse response) {
        LoginResponse loginResponse = userService.loginWithJwt(req.email(), req.password(), response);
        return ResponseEntity.ok(loginResponse);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<Response> sendPasswordResetOtp(@RequestBody ForgotPasswordRequest request) {
        Response response = userService.sendPasswordResetOtp(request.email());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> jwtLogout(
            HttpServletRequest request,
            HttpServletResponse response) {

        Map<String, Object> result = new HashMap<>();

        try {
            System.out.println("JWT Logout initiated");

            // Use comprehensive logout service
            logoutService.performCompleteLogout(request, response);

            result.put("message", "JWT logout successful");
            result.put("timestamp", System.currentTimeMillis());
            result.put("status", "SUCCESS");
            return ResponseEntity.ok(result);

        } catch (Exception e) {
            System.err.println("JWT logout error: " + e.getMessage());
            e.printStackTrace();

            // Still try cleanup
            try {
                logoutService.performCompleteLogout(request, response);
            } catch (Exception cleanupError) {
                System.err.println("Cleanup error: " + cleanupError.getMessage());
            }

            result.put("error", "JWT logout failed but cleanup attempted");
            result.put("message", e.getMessage());
            result.put("status", "PARTIAL_SUCCESS");
            return ResponseEntity.status(500).body(result);
        }
    }
}