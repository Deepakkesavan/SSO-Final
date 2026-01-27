package com.clarium.clarium_sso.config;

import com.clarium.clarium_sso.constant.ApplicationConstants;
import com.clarium.clarium_sso.dto.Cors;
import com.clarium.clarium_sso.dto.EnvironmentUrl;
import com.clarium.clarium_sso.dto.RedirectUrl;
import com.clarium.clarium_sso.security.JwtAuthFilter;
import com.clarium.clarium_sso.security.OAuth2FailureHandler;
import com.clarium.clarium_sso.service.UserService;
import com.clarium.clarium_sso.util.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static com.clarium.clarium_sso.constant.ApplicationConstants.*;
import static com.clarium.clarium_sso.constant.ExceptionConstants.*;

@Configuration
public class SecurityConfig {

    private final Cors corsConfig;
    private final JwtAuthFilter jwtAuthFilter;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final UserService userService;
    private final EnvironmentUrl environmentUrl;
    private final OAuth2FailureHandler oAuth2FailureHandler;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RedirectUrl redirectUrl;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter,
                          UserDetailsService userDetailsService,
                          PasswordEncoder passwordEncoder,
                          JwtUtil jwtUtil,
                          @Lazy UserService userService,
                          EnvironmentUrl environmentUrl,
                          Cors corsConfig,
                          OAuth2FailureHandler oAuth2FailureHandler,
                          RedirectUrl redirectUrl) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.userService = userService;
        this.environmentUrl = environmentUrl;
        this.corsConfig = corsConfig;
        this.oAuth2FailureHandler = oAuth2FailureHandler;
        this.redirectUrl = redirectUrl;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        requestHandler.setCsrfRequestAttributeName(null);

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
//                .csrf(csrf -> csrf
//                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                        .csrfTokenRequestHandler(requestHandler)
//                        .ignoringRequestMatchers(
//                                "/custom-login/auth/**",
//                                "/api/auth/**",
//                                "/login/**",
//                                "/oauth2/**",
//                                "/logout"
//                        )
//                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/custom-login/auth/**",
                                "/api/auth/validate",
                                "/api/auth/refresh-token",
                                "/api/auth/logout",
                                "/api/auth/failure",
                                "/api/auth/auth-status",
                                "/api/auth/token",
                                "/api/auth/authtoken",
                                "/login/**",
                                "/oauth2/**",
                                "/error",
                                "/"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(customAuthenticationEntryPoint())
                        .accessDeniedHandler(customAccessDeniedHandler())
                )
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(oAuth2SuccessHandler())
                        .failureHandler(oAuth2FailureHandler)
                )
                .requestCache(RequestCacheConfigurer::disable)
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(customLogoutSuccessHandler())
                        .deleteCookies(ApplicationConstants.JSESSION_ID, XSRF_TOKEN,
                                ApplicationConstants.JWT, REFRESH_TOKEN)
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .permitAll()
                )
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public LogoutSuccessHandler customLogoutSuccessHandler() {
        return (request, response, authentication) -> {
            // Clear all authentication cookies
            clearCookie(response, ApplicationConstants.JWT);
            clearCookie(response, ApplicationConstants.JSESSION_ID);
            clearCookie(response, XSRF_TOKEN);
            clearCookie(response, REFRESH_TOKEN);

            // Invalidate session if exists
            if (request.getSession(false) != null) {
                request.getSession().invalidate();
            }

            // Set no-cache headers
            response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
            response.setHeader("Pragma", "no-cache");
            response.setHeader("Expires", "0");

            response.setContentType(APPLICATION_CONSTANTS);
            response.setCharacterEncoding(UTF_8);
            response.setStatus(HttpServletResponse.SC_OK);

            String jsonResponse = "{\"message\":\"Logout successful\",\"timestamp\":\"" +
                    System.currentTimeMillis() + "\",\"status\":\"SUCCESS\"}";
            response.getWriter().write(jsonResponse);
            response.getWriter().flush();
        };
    }

    private void clearCookie(HttpServletResponse response, String name) {
        Cookie cookie = new Cookie(name, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // Set to true in production with HTTPS
        cookie.setPath("/");
        cookie.setMaxAge(0);
        cookie.setAttribute(SAME_SITE, ApplicationConstants.LAX);
        response.addCookie(cookie);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(corsConfig.getAllowedOrigins());
        configuration.setAllowedMethods(corsConfig.getAllowedMethods());
        configuration.setAllowedHeaders(corsConfig.getAllowedHeaders());
        configuration.setAllowCredentials(corsConfig.isAllowCredentials());
        configuration.setMaxAge(3600L);
        configuration.setExposedHeaders(Arrays.asList("Authorization", "Set-Cookie"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public AuthenticationEntryPoint customAuthenticationEntryPoint() {
        return (request, response, authException) -> {
            String uri = request.getRequestURI();

            response.setContentType(APPLICATION_CONSTANTS);
            response.setCharacterEncoding(UTF_8);

            if (uri.startsWith("/api/") || uri.startsWith("/custom-login/")) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

                // Build structured error response
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("id", (int) (Math.random() * 5000) + 5000);
                errorResponse.put("error", AUTHENTICATION_REQUIRED);
                errorResponse.put("errorCode", CODE_INVALID_CREDENTIALS);
                errorResponse.put("errorModule", MODULE_AUTHENTICATION);
                errorResponse.put("message", authException.getMessage());
                errorResponse.put("status", FAILED);
                errorResponse.put("timestamp", System.currentTimeMillis());

                response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
            } else {
                response.setStatus(HttpServletResponse.SC_FOUND);
                response.setHeader("Location", "/oauth2/authorization/azure");
            }
        };
    }

    @Bean
    public AccessDeniedHandler customAccessDeniedHandler() {
        return (request, response, ex) -> {
            String uri = request.getRequestURI();

            response.setContentType(APPLICATION_CONSTANTS);
            response.setCharacterEncoding(UTF_8);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);

            // Build structured error response
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("id", (int) (Math.random() * 5000) + 5000);
            errorResponse.put("error", ACCESS_DENIED);
            errorResponse.put("errorCode", CODE_OAUTH2_ACCESS_DENIED);
            errorResponse.put("errorModule", MODULE_SECURITY);
            errorResponse.put("message", ex.getMessage());
            errorResponse.put("status", FAILED);
            errorResponse.put("timestamp", System.currentTimeMillis());

            response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        };
    }

    @Bean
    public AuthenticationSuccessHandler oAuth2SuccessHandler() {
        return (request, response, authentication) -> {
            try {
                String email = ((org.springframework.security.oauth2.core.user.DefaultOAuth2User)
                        authentication.getPrincipal()).getAttribute("email");

                int empId = 0;
                String designation = "Unknown";

                try {
                    empId = userService.getEmpIdByEmail(email);
                    UUID desgnId = userService.getDesgnIdByEmpId(empId);
                    designation = userService.getDesignationById(desgnId);
                } catch (Exception e) {
                    System.err.println("Error getting employee info: " + e.getMessage());
                    e.printStackTrace();
                }
                String host = request.getHeader("Host");
                System.out.println("Request_Client_URL : " + host);

                String Success_URL = redirectUrl.getRedirects().stream()
                        .filter(r -> host.equals(r.getHost()))          // lambda required
                        .map(RedirectUrl.Redirect::getRedirectUrl)      // method reference
                        .findFirst()
                        .orElse("");

                // Generate access token
                String jwtToken = jwtUtil.generateToken(email, empId, designation);

                // Generate refresh token
                String refreshToken = jwtUtil.generateRefreshToken(email, empId, designation);

                // Set JWT cookie
                Cookie jwtCookie = new Cookie(ApplicationConstants.JWT, jwtToken);
                jwtCookie.setHttpOnly(true);
                jwtCookie.setSecure(false); // Set to true in production
                jwtCookie.setPath("/");
                jwtCookie.setMaxAge(60 * 60 * 2); // 2 hours
                jwtCookie.setAttribute(SAME_SITE, ApplicationConstants.LAX);
                response.addCookie(jwtCookie);

                System.out.println("================================================");
                System.out.println("OAuth2 Login Successful");
                System.out.println("Email: " + email);
                System.out.println("Employee ID: " + empId);
                System.out.println("Designation: " + designation);
                System.out.println("JWT Token: " + jwtToken.substring(0, 20) + "...");
                System.out.println("JWT expires at: " +
                        new Date(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(2)));
                System.out.println("================================================");

                // Set refresh token cookie
                Cookie refreshCookie = new Cookie(REFRESH_TOKEN, refreshToken);
                refreshCookie.setHttpOnly(true);
                refreshCookie.setSecure(false); // Set to true in production
                refreshCookie.setPath("/");
                refreshCookie.setMaxAge(60 * 60 * 60); // 60 hours
                refreshCookie.setAttribute(SAME_SITE, ApplicationConstants.LAX);
                response.addCookie(refreshCookie);

                response.sendRedirect(Success_URL);

            } catch (Exception e) {
                System.err.println("OAuth2 Success Handler Error: " + e.getMessage());
                e.printStackTrace();

                // Redirect to failure URL with error parameter
                String failureUrl = environmentUrl.getFailureurl();
                String separator = failureUrl.contains("?") ? "&" : "?";
                response.sendRedirect(failureUrl + separator + "error=processing_failed");
            }
        };
    }
}