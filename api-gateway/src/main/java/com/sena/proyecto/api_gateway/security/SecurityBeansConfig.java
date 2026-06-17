package com.sena.proyecto.api_gateway.security;

import co.edu.sena.security.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * El gateway define su propio JwtService a partir del secreto del entorno.
 * No depende del JwtConfig de ga-lib-security: ese se carga por component-scan
 * solo en los micros que escanean co.edu.sena.security, y el gateway no lo hace.
 */
@Configuration
public class SecurityBeansConfig {

    @Bean
    public JwtService jwtService(
            @Value("${security.secret}") String secret,
            @Value("${security.expiration-ms}") long expirationMs,
            @Value("${security.refresh-threshold-ms:300000}") long refreshThresholdMs) {
        return new JwtService(secret, expirationMs, refreshThresholdMs);
    }
}
