package com.Dotsquares.BoilerPlateAuth.Entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "logs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Log {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String eventType;
    private String email;
    private int statusCode;
    private String message;
    private LocalDateTime timestamp = LocalDateTime.now();
    @Column(nullable = false) // Ensure a value is provided
    private Integer errorCode;
}