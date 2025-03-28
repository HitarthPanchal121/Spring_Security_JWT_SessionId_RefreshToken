package com.Dotsquares.BoilerPlateAuth.Repository;

import com.Dotsquares.BoilerPlateAuth.Entity.Log;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface LogRepository extends JpaRepository<Log,Long> {
}
