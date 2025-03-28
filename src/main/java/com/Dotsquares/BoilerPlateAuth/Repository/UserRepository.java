package com.Dotsquares.BoilerPlateAuth.Repository;
import com.Dotsquares.BoilerPlateAuth.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);

    @Query(value = "SELECT * FROM users WHERE session_id = :sessionId AND jwt_token = :token", nativeQuery = true)
    Optional<User> getSessoinId(@Param("sessionId") String sessionId, @Param("token") String token);

}
