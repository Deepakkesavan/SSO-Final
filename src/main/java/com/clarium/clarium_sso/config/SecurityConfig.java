package com.clarium.clarium_sso.config;

import com.clarium.clarium_sso.constant.ApplicationConstants;
import com.clarium.clarium_sso.security.JwtAuthFilter;
import com.clarium.clarium_sso.service.UserService;
import com.clarium.clarium_sso.util.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static com.clarium.clarium_sso.constant.ApplicationConstants.ACCESS_DENIED;
import static com.clarium.clarium_sso.constant.ApplicationConstants.APPLICATION_CONSTANTS;
import static com.clarium.clarium_sso.constant.ApplicationConstants.FAILURE_URL;
import static com.clarium.clarium_sso.constant.ApplicationConstants.REFRESH_TOKEN;
import static com.clarium.clarium_sso.constant.ApplicationConstants.SAME_SITE;
import static com.clarium.clarium_sso.constant.ApplicationConstants.UTF_8;
import static com.clarium.clarium_sso.constant.ApplicationConstants.XSRF_TOKEN;

@Configuration
public class SecurityConfig {


    @Value("${cors.allowed-origins}")
    private String allowedOrigins;

    private final JwtAuthFilter jwtAuthFilter;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final UserService userService;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter,
                          UserDetailsService userDetailsService,
                          PasswordEncoder passwordEncoder,
                          JwtUtil jwtUtil,
                          @Lazy UserService userService) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.userService = userService;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        requestHandler.setCsrfRequestAttributeName(null);

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(requestHandler)
                        .ignoringRequestMatchers(
                                "/custom-login/auth/**",
                                "/api/auth/**",
                                "/login/**",
                                "/oauth2/**",
                                "/logout"
                        )
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/custom-login/auth/**",
                                "/api/auth/validate",
                                "/api/auth/refresh-token",
                                "/api/auth/logout",
                                "/api/auth/failure",
                                "/api/auth/auth-status",
                                "/login/**",
                                "/oauth2/**",
                                "/logout",
                                "/error"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(customAuthenticationEntryPoint())
                        .accessDeniedHandler(customAccessDeniedHandler())
                )
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(oAuth2SuccessHandler())
                        .failureUrl(FAILURE_URL)
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(customLogoutSuccessHandler())
                        .deleteCookies(ApplicationConstants.JSESSION_ID, XSRF_TOKEN, ApplicationConstants.JWT, REFRESH_TOKEN)
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .permitAll()
                )
                // Fixed session management
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // Changed to STATELESS for JWT
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
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
        configuration.setAllowedOriginPatterns(Arrays.asList(allowedOrigins.split(",")));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
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

            if (uri.startsWith("ssoapi/api/") || uri.startsWith("/custom-login/")) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"error\":\"Authentication required\",\"message\":\"" +
                        authException.getMessage() + "\",\"status\":\"UNAUTHORIZED\"}");
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

            if (uri.startsWith("/api/") || uri.startsWith("/custom-login/")) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.getWriter().write("{\"error\":\"Access denied\",\"message\":\"" +
                        ex.getMessage() + "\",\"status\":\"FORBIDDEN\"}");
            } else {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.getWriter().write(ACCESS_DENIED);
            }
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
                }

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

                // Set refresh token cookie
                Cookie refreshCookie = new Cookie(REFRESH_TOKEN, refreshToken);
                refreshCookie.setHttpOnly(true);
                refreshCookie.setSecure(false); // Set to true in production
                refreshCookie.setPath("/");
                refreshCookie.setMaxAge(60 * 60); // 1 hour (same as refresh token expiration)
                refreshCookie.setAttribute(SAME_SITE, ApplicationConstants.LAX);
                response.addCookie(refreshCookie);

                response.sendRedirect(ApplicationConstants.SUCCESS_URL);

            } catch (Exception e) {
                System.err.println("OAuth2 success handler error: " + e.getMessage());
                response.sendRedirect("http://localhost:5050/login?error=oauth_processing_failed");
            }
        };
    }
}