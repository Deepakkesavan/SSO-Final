package com.clarium.clarium_sso.service;

import com.clarium.clarium_sso.dto.LoginResponse;
import com.clarium.clarium_sso.dto.Response;
import com.clarium.clarium_sso.exception.*;
import com.clarium.clarium_sso.model.*;
import com.clarium.clarium_sso.repository.*;
import com.clarium.clarium_sso.util.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Random;
import java.util.UUID;

import static com.clarium.clarium_sso.constant.ApplicationConstants.*;
import static com.clarium.clarium_sso.constant.ApplicationConstants.MESSAGE_PASSWORD_RESET_PREFIX;
import static com.clarium.clarium_sso.constant.ApplicationConstants.MESSAGE_VALIDITY_SUFFIX;
import static com.clarium.clarium_sso.constant.ApplicationConstants.RESPONSE_PASSWORD_RESET_SENT;
import static com.clarium.clarium_sso.constant.ApplicationConstants.SUBJECT_PASSWORD_RESET;

@Service
public class UserService {

    private final UserRepository userRepo;
    private final EmployeeRepository employeeRepository;
    private final WorkInfoRepository workInfoRepository;
    private final DesignationRepository designationRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final OtpRepository otpRepository;
    private final EmailService emailService;

    public UserService(
            JwtUtil jwtUtil,
            AuthenticationManager authenticationManager,
            PasswordEncoder passwordEncoder,
            DesignationRepository designationRepository,
            WorkInfoRepository workInfoRepository,
            UserRepository userRepo,
            EmployeeRepository employeeRepository,
            OtpRepository otpRepository,
            EmailService emailService
    ) {
        this.authenticationManager = authenticationManager;
        this.workInfoRepository = workInfoRepository;
        this.userRepo = userRepo;
        this.employeeRepository = employeeRepository;
        this.designationRepository = designationRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.otpRepository = otpRepository;
        this.emailService = emailService;
    }

    // -------------------- REGISTER --------------------
    public User register(User user) {
        if (userRepo.existsByEmail(user.getEmail())) {
            throw new EmailAlreadyExistsException(EMAIL_ALREADY_REGISTERED);
        }
        if (userRepo.existsByUsername(user.getUsername())) {
            throw new UsernameAlreadyExistsException(USERNAME_ALREADY_TAKEN);
        }
        if (!employeeRepository.existsByEmail(user.getEmail())) {
            throw new NotAnEmployeeException(EMAIL_NOT_REGISTERED_AS_EMPLOYEE);
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    // -------------------- EMPLOYEE INFO --------------------
    public Integer getEmpIdByEmail(String email) {
        return employeeRepository.findByEmail(email)
                .map(Employee::getEmpId)
                .orElseThrow(() -> new ResourceNotFoundException(NO_EMPLOYEE_FOUND_WITH_EMAIL + email));
    }

    public UUID getDesgnIdByEmpId(int empId) {
        return workInfoRepository.findByEmpId(empId)
                .map(WorkInfo::getDesgnId)
                .orElseThrow(() -> new ResourceNotFoundException(NO_DESIGNATION_ID_FOR_EMPLOYEE_ID + empId));
    }

    public String getDesignationById(UUID id) {
        return designationRepository.findById(id)
                .map(Designation::getDesignation)
                .orElseThrow(() -> new ResourceNotFoundException(NO_DESIGNATION_FOUND_WITH_ID + id));
    }

    public Response sendPasswordResetOtp(String email) {

        if (!userRepo.existsByEmail(email)) {
            throw new ResourceNotFoundException(USER_NOT_FOUND_WITH_EMAIL_ID + email);
        }

        String otpCode = String.valueOf(100000 + new Random().nextInt(900000));
        otpRepository.findByEmail(email);
        Otp otp = new Otp();
        otp.setEmail(email);
        otp.setOtpCode(otpCode);
        otp.setExpiry(LocalDateTime.now().plusMinutes(10));
        otpRepository.save(otp);

        emailService.sendOtp(email, otpCode, SUBJECT_PASSWORD_RESET, MESSAGE_PASSWORD_RESET_PREFIX, MESSAGE_VALIDITY_SUFFIX);
        return new Response(RESPONSE_PASSWORD_RESET_SENT, email);
    }

    // -------------------- LOGIN WITH JWT --------------------
    public LoginResponse loginWithJwt(String email, String rawPassword, HttpServletResponse response) {
        try {
            // Authenticate user
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, rawPassword)
            );

            Employee user = employeeRepository.findByEmail(email)
                    .orElseThrow(() -> new ResourceNotFoundException(USER_NOT_FOUND_WITH_EMAIL_ID + email));

            // Get empId & designation
            int empId = getEmpIdByEmail(user.getEmail());
            UUID desgnId = getDesgnIdByEmpId(empId);
            String designation = getDesignationById(desgnId);

            // Generate JWT with empId & designation
            String token = jwtUtil.generateToken(user.getEmail(), empId, designation);

            // Set JWT cookie
            Cookie jwtCookie = new Cookie(JWT_TOKEN_TYPE, token);
            jwtCookie.setHttpOnly(true);
            jwtCookie.setSecure(false); // true in prod
            jwtCookie.setPath("/");
            jwtCookie.setMaxAge(60 * 60 * 2); // 2 hours
            jwtCookie.setAttribute("SameSite", "Lax");
            response.addCookie(jwtCookie);

            response.setHeader("Access-Control-Allow-Credentials", "true");

            return new LoginResponse(LOGIN_SUCCESSFUL, empId, designation);

        } catch (Exception e) {
            throw new InvalidCredentialsException(INVALID_EMAIL_OR_PASSWORD);
        }
    }
}
