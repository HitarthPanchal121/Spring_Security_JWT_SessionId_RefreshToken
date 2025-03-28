package com.Dotsquares.BoilerPlateAuth.Config;
import com.Dotsquares.BoilerPlateAuth.Entity.RefreshToken;
import com.Dotsquares.BoilerPlateAuth.Entity.User;
import com.Dotsquares.BoilerPlateAuth.Repository.RefreshTokenRepository;
import com.Dotsquares.BoilerPlateAuth.Repository.UserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.time.Instant;
import java.util.Optional;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7); // Extract JWT token

        try {
            // ✅ Extract user email from token
            String userEmail = jwtUtil.extractEmail(token);

            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

                if (jwtUtil.validateToken(token)) {
                    // ✅ Set authentication if token is valid
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } else {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Token");
                    return;
                }
            }
        } catch (ExpiredJwtException e) {
            // ✅ Handle Expired Token
            String userEmail = e.getClaims().getSubject();

            if (userEmail != null) {
                Optional<User> userOpt = userRepository.findByEmail(userEmail);
                if (userOpt.isPresent()) {
                    User user = userOpt.get();
                    Optional<RefreshToken> refreshTokenOpt = refreshTokenRepository.findByUserId(user.getId());

                    if (refreshTokenOpt.isPresent() && refreshTokenOpt.get().getExpiryDate().isAfter(Instant.now())) {
                        // ✅ Generate new access token
                        String newAccessToken = jwtUtil.generateToken(userEmail);

                        // ✅ Overwrite the new access token in `users` table
                        user.setJwtToken(newAccessToken);
                        userRepository.save(user);

                        // ✅ Return new token in response
                        response.setContentType("application/json");
                        response.setCharacterEncoding("UTF-8");
                        response.getWriter().write("{ \"resultCode\": 201, \"resultMessage\": \"Access token expired. A new token has been generated.\", \"newAccessToken\": \"" + newAccessToken + "\" }");
                        return;
                    }
                }
            }

            // ❌ No valid refresh token, force user to log in again
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Access token expired. Please login again.");
            return;
        }

        filterChain.doFilter(request, response);
    }


}