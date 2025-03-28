package com.Dotsquares.BoilerPlateAuth.Repository;

import com.Dotsquares.BoilerPlateAuth.Entity.RefreshToken;
import com.Dotsquares.BoilerPlateAuth.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken,Long> {

    Optional<RefreshToken> findByToken(String token);
    Optional<RefreshToken> findByUser(User user);
    Optional<RefreshToken> findByUserId(Long userId);
    void deleteByUser(User user);
}
