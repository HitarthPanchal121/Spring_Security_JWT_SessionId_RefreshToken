package com.Dotsquares.BoilerPlateAuth.Service;

import com.Dotsquares.BoilerPlateAuth.Config.JwtUtil;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    private final JwtUtil jwtUtil;

    public JwtService(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    public boolean isTokenValid(String token) {
        return jwtUtil.validateToken(token);
    }
}