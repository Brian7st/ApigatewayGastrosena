package com.sena.proyecto.api_gateway.security;

import co.edu.sena.security.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Único punto de validación del JWT. Corre antes del ruteo del gateway:
 *  - Bloquea (401) toda request sin token válido, salvo rutas públicas.
 *  - Inyecta la identidad downstream con headers X-User-* para que los micros confíen.
 *  - Elimina cualquier X-User-* entrante del cliente (anti-spoofing): los micros
 *    NO deben exponer puerto al host, así el único que puede setearlos es el gateway.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String H_USER_ID = "X-User-Id";
    private static final String H_USER_EMAIL = "X-User-Email";
    private static final String H_USER_ROL = "X-User-Rol";
    private static final String H_USER_NOMBRE = "X-User-Nombre";

    private final JwtService jwtService;
    private final List<String> publicPaths;

    public JwtAuthenticationFilter(JwtService jwtService,
                                   @Value("${security.public-paths:/api/auth,/auth,/actuator}") String publicPaths) {
        this.jwtService = jwtService;
        this.publicPaths = Arrays.stream(publicPaths.split(",")).map(String::trim).toList();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        // CORS preflight: dejar pasar para que lo resuelva el CorsFilter.
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        String path = request.getRequestURI();

        if (isPublic(path)) {
            // Rutas públicas: inyectar identidad de invitado (los micros requieren
            // X-User-* para aceptar la request, pero sin privilegios).
            chain.doFilter(guestIdentityHeaders(request), response);
            return;
        }

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            unauthorized(response, "Falta el token de autenticación");
            return;
        }

        String token = authHeader.substring(7);
        if (!jwtService.isValidToken(token)) {
            unauthorized(response, "Token inválido o expirado");
            return;
        }

        Map<String, String> identity = new HashMap<>();
        try {
            identity.put(H_USER_ID, jwtService.extractUserId(token).toString());
            identity.put(H_USER_EMAIL, jwtService.extractUserName(token));
            identity.put(H_USER_ROL, jwtService.extractNombreRol(token));
            identity.put(H_USER_NOMBRE, jwtService.extractNombreCompleto(token));
        } catch (RuntimeException e) {
            unauthorized(response, "Token con claims inválidos");
            return;
        }

        chain.doFilter(withIdentityHeaders(request, identity), response);
    }

    private boolean isPublic(String path) {
        return publicPaths.stream().anyMatch(p -> path.equals(p) || path.startsWith(p + "/") || path.startsWith(p));
    }

    private void unauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"" + message + "\"}");
    }

    /** Wrapper que inyecta identidad de invitado (rutas públicas). */
    private HttpServletRequest guestIdentityHeaders(HttpServletRequest request) {
        Map<String, String> guest = new HashMap<>();
        guest.put(H_USER_ID, "");
        guest.put(H_USER_EMAIL, "");
        guest.put(H_USER_ROL, "PUBLIC");
        guest.put(H_USER_NOMBRE, "Invitado");
        return withIdentityHeaders(request, guest);
    }

    /** Wrapper que reemplaza los X-User-* por los valores derivados del token. */
    private HttpServletRequest withIdentityHeaders(HttpServletRequest request, Map<String, String> identity) {
        Map<String, String> override = new HashMap<>();
        for (String h : List.of(H_USER_ID, H_USER_EMAIL, H_USER_ROL, H_USER_NOMBRE)) {
            override.put(h.toLowerCase(Locale.ROOT), identity.get(h));
        }
        return new HttpServletRequestWrapper(request) {
            @Override
            public String getHeader(String name) {
                String key = name.toLowerCase(Locale.ROOT);
                if (override.containsKey(key)) {
                    return override.get(key); // null = header ausente
                }
                return super.getHeader(name);
            }

            @Override
            public Enumeration<String> getHeaders(String name) {
                String key = name.toLowerCase(Locale.ROOT);
                if (override.containsKey(key)) {
                    String v = override.get(key);
                    return v == null ? Collections.emptyEnumeration()
                            : Collections.enumeration(List.of(v));
                }
                return super.getHeaders(name);
            }

            @Override
            public Enumeration<String> getHeaderNames() {
                List<String> names = new ArrayList<>();
                Enumeration<String> original = super.getHeaderNames();
                while (original.hasMoreElements()) {
                    String n = original.nextElement();
                    if (!override.containsKey(n.toLowerCase(Locale.ROOT))) {
                        names.add(n);
                    }
                }
                override.forEach((k, v) -> {
                    if (v != null) {
                        names.add(k);
                    }
                });
                return Collections.enumeration(names);
            }
        };
    }
}
