package com.Dotsquares.BoilerPlateAuth.Controller;
import com.Dotsquares.BoilerPlateAuth.Config.JwtUtil;
import com.Dotsquares.BoilerPlateAuth.Config.SessionIdGenerator;
import com.Dotsquares.BoilerPlateAuth.Entity.Log;
import com.Dotsquares.BoilerPlateAuth.Entity.RefreshToken;
import com.Dotsquares.BoilerPlateAuth.Entity.User;
import com.Dotsquares.BoilerPlateAuth.Repository.LogRepository;
import com.Dotsquares.BoilerPlateAuth.Repository.RefreshTokenRepository;
import com.Dotsquares.BoilerPlateAuth.Repository.UserRepository;
import com.Dotsquares.BoilerPlateAuth.Service.JwtService;
import com.Dotsquares.BoilerPlateAuth.errorHandling.BaseResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private  UserRepository userRepository;

    @Autowired
    private  LogRepository logRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private  JwtService jwtService;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody User request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            logRepository.save(new Log(null, "REGISTER_FAILED", request.getEmail(), 400, "Email already exists", LocalDateTime.now(),400));
            return ResponseEntity.ok(new BaseResponse<>(
                    HttpStatus.BAD_REQUEST.value(),
                    "Email already registered"
            ));
        }

        request.setPassword(passwordEncoder.encode(request.getPassword()));
        User savedUser= userRepository.save(request);
        logRepository.save(new Log(null, "REGISTER_SUCCESS", request.getEmail(), 201, "User registered successfully", LocalDateTime.now(),0));
        return ResponseEntity.ok(new BaseResponse<>(
                HttpStatus.CREATED.value(),
                "User Registered Successfully!!"
        ));
    }
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody User request, HttpServletRequest httpRequest) {
        User user = userRepository.findByEmail(request.getEmail()).orElse(null);

        if (user == null || !passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        // ✅ Extract Client IP
        String ipAddress = getClientIpAddress(httpRequest);

        // ✅ Generate Session ID
        String sessionId = SessionIdGenerator.generateSessionId(user, ipAddress);

        // ✅ Generate Tokens
        String accessToken = jwtUtil.generateToken(user.getEmail());
        String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());

        // ✅ Remove old refresh token (if exists)
        refreshTokenRepository.findByUser(user).ifPresent(refreshTokenRepository::delete);

        // ✅ Save new refresh token
        RefreshToken refreshTokenEntity = new RefreshToken(
                null,
                user,
                refreshToken,
                Instant.now().plus(7, ChronoUnit.DAYS) // 7 days expiry
        );
        refreshTokenRepository.save(refreshTokenEntity);

        // ✅ Store session ID and Access Token in User
        user.setSessionId(sessionId);
        user.setJwtToken(accessToken);
        userRepository.save(user);

        // ✅ Response with Access Token, Refresh Token & Session ID
        Map<String, String> response = new HashMap<>();
        response.put("accessToken", accessToken);
        response.put("sessionId", sessionId);

        return ResponseEntity.ok(response);
    }

    // ✅ Extract client IP (Handles proxies)
    private String getClientIpAddress(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip.split(",")[0]; // If multiple IPs, take the first
    }


    @GetMapping("/all")
    public ResponseEntity<?> getAllUsers(@RequestHeader("Authorization") String token) {
        try {
            // Extract token from "Bearer <token>" format
            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            }

            // Validate token
            if (!jwtService.isTokenValid(token)) {
                return ResponseEntity.ok(new BaseResponse<>(
                        HttpStatus.UNAUTHORIZED.value(),
                        "Invalid or Expired Token"
                ));
            }

            // Fetch all users from database
            List<User> users = userRepository.findAll();
            return ResponseEntity.ok(new BaseResponse<>(
                    HttpStatus.OK.value(),
                    "VERIFIED!!",
                    users
            ));
        } catch (Exception e) {
            System.err.println("Error in /auth/all: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred while processing the request.");
        }
    }

    @GetMapping("/test")
    public ResponseEntity<?> test() {
        return ResponseEntity.ok(new BaseResponse<>(
                HttpStatus.OK.value(),
                "Test Successful!!"
        ));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        // Check if refreshToken is missing
        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Refresh token is required");
        }

        // Fetch the refresh token from the database
        Optional<RefreshToken> storedTokenOpt = refreshTokenRepository.findByToken(refreshToken);

        // Check if token exists
        if (storedTokenOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }

        RefreshToken storedToken = storedTokenOpt.get();

        // Check if the refresh token is expired
        if (storedToken.getExpiryDate().isBefore(Instant.now())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Expired refresh token");
        }

        // Retrieve the associated user
        User user = storedToken.getUser();

        // Generate a new JWT token
        String newToken = jwtUtil.generateToken(user.getEmail());

        // Overwrite the existing JWT token in the users table
        user.setJwtToken(newToken);  // Assuming 'jwtToken' is a column in the users table
        userRepository.save(user);   // Save the updated user entity

        // Return the new JWT token in the response
        Map<String, String> response = new HashMap<>();
        response.put("New Generated JWT token : ", newToken);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/ww")
    public String ww(){
        return "Working Good";
    }
}