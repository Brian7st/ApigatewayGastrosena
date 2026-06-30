package com.sena.proyecto.api_gateway.security;

import co.edu.sena.security.JwtService;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthenticationFilterTest {

    private static final String SECRET = Base64.getEncoder()
            .encodeToString("12345678901234567890123456789012".getBytes(StandardCharsets.UTF_8));

    private final JwtService jwtService = new JwtService(SECRET, 60_000, 10_000);
    private final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtService, "/api/auth,/auth,/actuator");

    @Test
    void forwardsFullNameFromJwtAsInternalHeader() throws Exception {
        UUID userId = UUID.randomUUID();
        String token = jwtService.generateToken(
                userId,
                UUID.randomUUID(),
                "ana@example.com",
                "MESERO",
                "Ana Gomez"
        );

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/pedidos");
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        ServletRequest forwardedRequest = chain.getRequest();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(forwardedRequest).isNotNull();
        HttpServletRequest httpRequest = (HttpServletRequest) forwardedRequest;
        assertThat(httpRequest.getHeader("X-User-Id")).isEqualTo(userId.toString());
        assertThat(httpRequest.getHeader("X-User-Email")).isEqualTo("ana@example.com");
        assertThat(httpRequest.getHeader("X-User-Rol")).isEqualTo("MESERO");
        assertThat(httpRequest.getHeader("X-User-Nombre")).isEqualTo("Ana Gomez");
    }
}
