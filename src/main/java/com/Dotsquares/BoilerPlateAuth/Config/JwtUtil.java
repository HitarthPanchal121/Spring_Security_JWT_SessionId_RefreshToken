package com.Dotsquares.BoilerPlateAuth.Config;


import com.Dotsquares.BoilerPlateAuth.Entity.User;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long expirationTime;

    @Value("${refreshToken.expiration}")
    private long refreshTokenExpiration;

    public String generateToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    // ✅ Generate Refresh Token
    public String generateRefreshToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpiration))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    // ✅ Validate Token
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            System.out.println("JWT Token Expired: " + e.getMessage());
            return false; // This is needed to differentiate between expired and invalid tokens
        } catch (JwtException e) {
            System.out.println("Invalid JWT Token: " + e.getMessage());
            return false;
        }
    }

    // ✅ Extract Email
    public String extractEmail(String token) {
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

//    // Generate New JWT Using Refresh Token
//    public String refreshAccessToken(String refreshToken) {
//        try {
//            Claims claims = Jwts.parser()
//                    .setSigningKey(secretKey)
//                    .parseClaimsJws(refreshToken)
//                    .getBody();
//
//            String email = claims.getSubject();
//
//            // Check if Refresh Token is expired
//            if (claims.getExpiration().before(new Date())) {
//                throw new RuntimeException("Refresh Token Expired. Please log in again.");
//            }
//
//            // Generate new JWT
//            return "Updated Jwt Token: " + generateToken(email);
//
//        } catch (ExpiredJwtException e) {
//            throw new RuntimeException("Refresh Token Expired. Please log in again.");
//        } catch (JwtException e) {
//            throw new RuntimeException("Invalid Refresh Token.");
//        }
//    }
}

