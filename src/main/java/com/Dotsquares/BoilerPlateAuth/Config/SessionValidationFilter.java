package com.Dotsquares.BoilerPlateAuth.Config;

import com.Dotsquares.BoilerPlateAuth.Entity.User;
import com.Dotsquares.BoilerPlateAuth.Repository.UserRepository;
import com.Dotsquares.BoilerPlateAuth.errorHandling.BaseResponse;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Optional;

@Component
public class SessionValidationFilter implements Filter {

    private final UserRepository userRepository;

    public SessionValidationFilter(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;

        // List of public endpoints to bypass session validation
        String[] publicEndpoints = {"/auth/register", "/auth/login","/auth/refresh-token","/auth/ww"};

        // Check if the current request matches a public endpoint
        String path = httpRequest.getRequestURI();
        boolean isPublicEndpoint = Arrays.stream(publicEndpoints).anyMatch(path::startsWith);

        if (isPublicEndpoint) {
            // Skip session validation for public endpoints
            chain.doFilter(request, response);
            return;
        }

        // Validate Session-ID for protected endpoints
        String sessionId = httpRequest.getHeader("Session-ID");
        String token = httpRequest.getHeader("Authorization");
        if (sessionId == null || sessionId.isEmpty()) {
            // Create a BaseResponse object for missing Session-ID
            BaseResponse<?> baseResponse = BaseResponse.builder()
                    .resultCode(HttpStatus.BAD_REQUEST.value())
                    .resultMessage("Session ID is missing")
                    .build();

            // Write the BaseResponse object as JSON to the HttpServletResponse
            sendErrorResponse(response, baseResponse, HttpStatus.BAD_REQUEST);
            return;
        }
        token = token.substring(7);

        Optional<User> userOptional = userRepository.getSessoinId(sessionId,token);

        if (userOptional.isEmpty()) {
            // Create a BaseResponse object for invalid Session-ID
            BaseResponse<?> baseResponse = BaseResponse.builder()
                    .resultCode(HttpStatus.UNAUTHORIZED.value())
                    .resultMessage("Invalid session")
                    .build();

            // Write the BaseResponse object as JSON to the HttpServletResponse
            sendErrorResponse(response, baseResponse, HttpStatus.UNAUTHORIZED);
            return;
        }
        else if (userOptional!=null){
           String sessionID= userOptional.get().getSessionId();
           if (!sessionID.equals(sessionId)){
               // Create a BaseResponse object for invalid Session-ID
               BaseResponse<?> baseResponse = BaseResponse.builder()
                       .resultCode(HttpStatus.UNAUTHORIZED.value())
                       .resultMessage("Invalid session")
                       .build();

               // Write the BaseResponse object as JSON to the HttpServletResponse
               sendErrorResponse(response, baseResponse, HttpStatus.UNAUTHORIZED);
               return;
           }
        }

        chain.doFilter(request, response);
    }

    /**
     * Helper method to send a custom error response.
     *
     * @param response The HttpServletResponse object.
     * @param baseResponse The BaseResponse object to be serialized as JSON.
     * @param status The HTTP status code.
     * @throws IOException If an I/O error occurs.
     */
    private void sendErrorResponse(ServletResponse response, BaseResponse<?> baseResponse, HttpStatus status) throws IOException {
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.setStatus(status.value());
        httpResponse.setContentType("application/json");
        httpResponse.setCharacterEncoding("UTF-8");

        try (PrintWriter writer = httpResponse.getWriter()) {
            // Use Jackson ObjectMapper to serialize the BaseResponse object to JSON
            com.fasterxml.jackson.databind.ObjectMapper objectMapper = new com.fasterxml.jackson.databind.ObjectMapper();
            writer.write(objectMapper.writeValueAsString(baseResponse));
        }
    }
}