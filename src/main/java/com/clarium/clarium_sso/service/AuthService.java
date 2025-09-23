        package com.clarium.clarium_sso.service;

        import com.clarium.clarium_sso.dto.AzureUserAttributes;
        import com.clarium.clarium_sso.dto.LoginFailure;
        import com.clarium.clarium_sso.dto.UserAttributes;
        import com.clarium.clarium_sso.model.User;
        import com.clarium.clarium_sso.repository.UserRepository;
        import com.clarium.clarium_sso.util.JwtUtil;
        import io.jsonwebtoken.Claims;
        import io.jsonwebtoken.Jwts;
        import io.jsonwebtoken.security.Keys;
        import jakarta.servlet.http.Cookie;
        import jakarta.servlet.http.HttpServletResponse;
        import org.springframework.http.ResponseEntity;
        import org.springframework.security.core.Authentication;
        import org.springframework.security.core.context.SecurityContextHolder;
        import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
        import org.springframework.security.oauth2.core.user.OAuth2User;
        import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
        import org.springframework.stereotype.Service;

        import java.nio.charset.StandardCharsets;
        import java.security.Key;
        import java.util.Map;
        import java.util.UUID;

        import static com.clarium.clarium_sso.constant.ApplicationConstants.*;

        @Service
        public class AuthService {

            private final UserService userService;
            private final UserRepository userRepository;
            private final JwtUtil jwtUtil; // add this

            public AuthService(UserService userService, UserRepository userRepository, JwtUtil jwtUtil) {
                this.userService = userService;
                this.userRepository = userRepository;
                this.jwtUtil  = jwtUtil;
            }

            public ResponseEntity<Map<String, Object>> getUser(HttpServletResponse response) {
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();

                if (auth == null || !auth.isAuthenticated()) {
                    System.out.println("No valid authentication found");
                    return ResponseEntity.ok(Map.of(
                            "user", new AzureUserAttributes(false, 0, null, null),
                            "token", null
                    ));
                }

                AzureUserAttributes azureUser = null;

                try {
                    // 1️⃣ OAuth2AuthenticationToken
                    if (auth instanceof OAuth2AuthenticationToken || auth.getPrincipal() instanceof OAuth2User) {
                        OAuth2User oauthUser = (OAuth2User) auth.getPrincipal();
                        System.out.println("OAuth2 Authentication detected for email: " + oauthUser.getAttribute(OAUTH_ATTR_EMAIL));

                        UserAttributes userAttributes = new UserAttributes(
                                oauthUser.getAttribute(OAUTH_ATTR_GIVEN_NAME),
                                oauthUser.getAttribute(OAUTH_ATTR_FAMILY_NAME),
                                oauthUser.getAttribute(OAUTH_ATTR_NAME),
                                oauthUser.getAttribute(OAUTH_ATTR_SUB),
                                oauthUser.getAttribute(OAUTH_ATTR_EMAIL),
                                oauthUser.getAttribute(OAUTH_ATTR_PICTURE)
                        );

                        int empId;
                        String designation;
                        try {
                            empId = userService.getEmpIdByEmail(oauthUser.getAttribute(OAUTH_ATTR_EMAIL));
                            UUID desgnId = userService.getDesgnIdByEmpId(empId);
                            designation = userService.getDesignationById(desgnId);
                        } catch (Exception e) {
                            System.out.println("Employee info not found for OAuth2 user: " + e.getMessage());
                            empId = 0;
                            designation = null;
                        }

                        azureUser = new AzureUserAttributes(true, empId, designation, userAttributes);
                    }
                    // 2️⃣ UsernamePasswordAuthenticationToken (JWT login)
                    else if (auth instanceof UsernamePasswordAuthenticationToken && auth.getPrincipal() instanceof String) {
                        String email = (String) auth.getPrincipal();
                        System.out.println("JWT Authentication detected for email: " + email);

                        User user = userRepository.findByEmailIgnoreCase(email).orElse(null);
                        if (user != null) {
                            UserAttributes userAttributes = new UserAttributes(
                                    null,
                                    null,
                                    user.getUsername(),
                                    user.getId().toString(),
                                    user.getEmail(),
                                    null
                            );

                            int empId;
                            String designation;
                            try {
                                empId = userService.getEmpIdByEmail(user.getEmail());
                                UUID desgnId = userService.getDesgnIdByEmpId(empId);
                                designation = userService.getDesignationById(desgnId);
                            } catch (Exception e) {
                                System.out.println("Employee info not found for JWT user: " + e.getMessage());
                                empId = 0;
                                designation = "Unknown";
                            }

                            azureUser = new AzureUserAttributes(true, empId, designation, userAttributes);
                        }
                    }
                } catch (Exception e) {
                    System.out.println("Error resolving user: " + e.getMessage());
                    azureUser = new AzureUserAttributes(false, 0, null, null);
                }

                String token = null;
                if (azureUser != null && azureUser.isAuthenticated()) {
                    token = jwtUtil.generateToken(azureUser.getUserAttributes().getEmail(), azureUser.getEmpId(), azureUser.getDesignation());

                    // ✅ Set JWT in HTTP-only cookie
                    Cookie cookie = new Cookie("JWT", token);
                    cookie.setHttpOnly(true);
                    cookie.setSecure(true); // must be HTTPS
                    cookie.setPath("/");    // accessible for all paths
                    cookie.setMaxAge(24 * 60 * 60); // 1 day expiry

                    response.addCookie(cookie);
                }

                return ResponseEntity.ok(Map.of(
                        "user", azureUser,
                        "token", token // optional: can keep in body for SPA read if you want
                ));
            }

            public AzureUserAttributes getCurrentUser(HttpServletResponse response) {
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();

                if (auth == null || !auth.isAuthenticated()) {
                    return new AzureUserAttributes(false, 0, null, null);
                }

                AzureUserAttributes azureUser = null;

                try {
                    if (auth instanceof OAuth2AuthenticationToken || auth.getPrincipal() instanceof OAuth2User) {
                        OAuth2User oauthUser = (OAuth2User) auth.getPrincipal();

                        UserAttributes userAttributes = new UserAttributes(
                                oauthUser.getAttribute(OAUTH_ATTR_GIVEN_NAME),
                                oauthUser.getAttribute(OAUTH_ATTR_FAMILY_NAME),
                                oauthUser.getAttribute(OAUTH_ATTR_NAME),
                                oauthUser.getAttribute(OAUTH_ATTR_SUB),
                                oauthUser.getAttribute(OAUTH_ATTR_EMAIL),
                                oauthUser.getAttribute(OAUTH_ATTR_PICTURE)
                        );

                        int empId;
                        String designation;
                        try {
                            empId = userService.getEmpIdByEmail(oauthUser.getAttribute(OAUTH_ATTR_EMAIL));
                            UUID desgnId = userService.getDesgnIdByEmpId(empId);
                            designation = userService.getDesignationById(desgnId);
                        } catch (Exception e) {
                            empId = 0;
                            designation = null;
                        }

                        azureUser = new AzureUserAttributes(true, empId, designation, userAttributes);
                    } else if (auth instanceof UsernamePasswordAuthenticationToken && auth.getPrincipal() instanceof String) {
                        String email = (String) auth.getPrincipal();

                        User user = userRepository.findByEmailIgnoreCase(email).orElse(null);
                        if (user != null) {
                            UserAttributes userAttributes = new UserAttributes(
                                    null, null, user.getUsername(), user.getId().toString(), user.getEmail(), null
                            );

                            int empId;
                            String designation;
                            try {
                                empId = userService.getEmpIdByEmail(user.getEmail());
                                UUID desgnId = userService.getDesgnIdByEmpId(empId);
                                designation = userService.getDesignationById(desgnId);
                            } catch (Exception e) {
                                empId = 0;
                                designation = "Unknown";
                            }

                            azureUser = new AzureUserAttributes(true, empId, designation, userAttributes);
                        }
                    }
                } catch (Exception e) {
                    azureUser = new AzureUserAttributes(false, 0, null, null);
                }

                // Optionally refresh JWT
                if (azureUser != null && azureUser.isAuthenticated()) {
                    String token = jwtUtil.generateToken(azureUser.getUserAttributes().getEmail(), azureUser.getEmpId(), azureUser.getDesignation());
                    Cookie cookie = new Cookie("JWT", token);
                    cookie.setHttpOnly(true);
                    cookie.setSecure(true);
                    cookie.setPath("/");
                    cookie.setMaxAge(24 * 60 * 60);
                    response.addCookie(cookie);
                }

                return azureUser;
            }


//            public String getEmailFromRefreshToken(String refreshToken) {
//                try {
//                    return jwtUtil.extractUsername(refreshToken);
//                } catch (Exception e) {
//                    System.out.println("Invalid refresh token: " + e.getMessage());
//                    return null;
//                }
//            }

            public AzureUserAttributes getUserByEmail(String email) {
                // 1️⃣ Try DB first
                User user = userRepository.findByEmail(email).orElse(null);
                if (user != null) {
                    UserAttributes userAttributes = new UserAttributes(
                            null, null, user.getUsername(),
                            user.getId().toString(), user.getEmail(), null
                    );

                    int empId;
                    String designation;
                    try {
                        empId = userService.getEmpIdByEmail(user.getEmail());
                        UUID desgnId = userService.getDesgnIdByEmpId(empId);
                        designation = userService.getDesignationById(desgnId);
                    } catch (Exception e) {
                        empId = 0;
                        designation = "Unknown";
                    }

                    return new AzureUserAttributes(true, empId, designation, userAttributes);
                }

                // 2️⃣ Fall back to OAuth2 info if DB user not found
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                if (auth instanceof OAuth2AuthenticationToken || auth.getPrincipal() instanceof OAuth2User) {
                    OAuth2User oauthUser = (OAuth2User) auth.getPrincipal();
                    String oauthEmail = oauthUser.getAttribute("email"); // make sure attribute name matches

                    if (oauthEmail != null && oauthEmail.equalsIgnoreCase(email)) {
                        UserAttributes userAttributes = new UserAttributes(
                                oauthUser.getAttribute("given_name"),
                                oauthUser.getAttribute("family_name"),
                                oauthUser.getAttribute("name"),
                                oauthUser.getAttribute("sub"),
                                oauthEmail,
                                oauthUser.getAttribute("picture")
                        );

                        int empId;
                        String designation;
                        try {
                            empId = userService.getEmpIdByEmail(oauthEmail);
                            UUID desgnId = userService.getDesgnIdByEmpId(empId);
                            designation = userService.getDesignationById(desgnId);
                        } catch (Exception e) {
                            empId = 0;
                            designation = "Unknown";
                        }

                        return new AzureUserAttributes(true, empId, designation, userAttributes);
                    }
                }

                // 3️⃣ If nothing found
                return new AzureUserAttributes(false, 0, null, null);
            }

            private AzureUserAttributes buildAzureUserFromOAuth2(OAuth2User oauthUser) {
                UserAttributes userAttributes = new UserAttributes(
                        oauthUser.getAttribute(OAUTH_ATTR_GIVEN_NAME),
                        oauthUser.getAttribute(OAUTH_ATTR_FAMILY_NAME),
                        oauthUser.getAttribute(OAUTH_ATTR_NAME),
                        oauthUser.getAttribute(OAUTH_ATTR_SUB),
                        oauthUser.getAttribute(OAUTH_ATTR_EMAIL),
                        oauthUser.getAttribute(OAUTH_ATTR_PICTURE)
                );

                int empId;
                String designation;
                try {
                    empId = userService.getEmpIdByEmail(userAttributes.getEmail());
                    UUID desgnId = userService.getDesgnIdByEmpId(empId);
                    designation = userService.getDesignationById(desgnId);
                } catch (Exception e) {
                    empId = 0;
                    designation = null;
                }

                return new AzureUserAttributes(true, empId, designation, userAttributes);
            }

            private AzureUserAttributes buildAzureUserFromJwt(String email) {
                User user = userRepository.findByEmailIgnoreCase(email).orElse(null);
                if (user == null) return new AzureUserAttributes(false, 0, null, null);

                UserAttributes userAttributes = new UserAttributes(
                        null, null, user.getUsername(), user.getId().toString(), user.getEmail(), null
                );

                int empId;
                String designation;
                try {
                    empId = userService.getEmpIdByEmail(user.getEmail());
                    UUID desgnId = userService.getDesgnIdByEmpId(empId);
                    designation = userService.getDesignationById(desgnId);
                } catch (Exception e) {
                    empId = 0;
                    designation = "Unknown";
                }

                return new AzureUserAttributes(true, empId, designation, userAttributes);
            }






            public LoginFailure loginFailure(){
                return new LoginFailure(false, AUTHENTICATION_FAILED);
            }

            public void debugAllUsers(String tokenEmail) {
                System.out.println("=== DEBUG: Listing all emails in SsoUsers table ===");
                userRepository.findAll().forEach(u -> {
                    String dbEmail = u.getEmail();
                    boolean matches = dbEmail.equalsIgnoreCase(tokenEmail);
                    System.out.println("DB Email: '" + dbEmail + "' | Length: " + dbEmail.length()
                            + " | Matches token email? " + matches);
                });
                System.out.println("Token email: '" + tokenEmail + "' | Length: " + tokenEmail.length());
                System.out.println("=== END DEBUG ===");
            }

            // -------------------- Refresh token helper --------------------
            public String getEmailFromRefreshToken(String refreshToken) {
                // This delegates to JwtUtil
                return new JwtUtil().getEmailFromRefreshToken(refreshToken);
            }

        }