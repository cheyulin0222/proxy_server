package com.arplanets.auth.filter;

import com.arplanets.auth.component.TenantPerIssuerComponentRegistry;
import com.arplanets.auth.component.UserPoolContext;
import com.arplanets.auth.component.UserPoolContextHolder;
import com.arplanets.auth.model.po.domain.UserPool;
import com.arplanets.auth.repository.UserPoolRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.http.HttpHeaders;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RequiredArgsConstructor
@Slf4j
public class UserPoolValidationFilter extends OncePerRequestFilter {

    private final UserPoolRepository userPoolRepository;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {

        AuthorizationServerContext context = AuthorizationServerContextHolder.getContext();
        String issuer = context.getIssuer();

        log.trace("issuer= {}", issuer);

        String poolName = extractPathAfterDomain(issuer);

        log.trace("poolName= {}", poolName);

        if (poolName.isBlank()) {
            log.warn("Pool name not found in issuer : {}", issuer);
            sendErrorResponse(response, HttpStatus.BAD_REQUEST, "Missing or invalid poolName.");
            return;
        }

        UserPool userPool = userPoolRepository.findByPoolName(poolName);

        if (userPool == null) {
            log.warn("User pool not found for pool name: {}", poolName);
            sendErrorResponse(response, HttpStatus.NOT_FOUND, "User pool not found.");
            return;
        }

        String userPoolId = userPool.getUserPoolId();
        UserPoolContextHolder.setContext(new UserPoolContext(userPoolId, userPool));
        log.debug("Set UserPoolContext for User Pool ID '{}'", userPoolId);

        try {
            filterChain.doFilter(request, response);
        } finally {
            UserPoolContextHolder.clearContext();
            log.debug("Cleared UserPoolContext for User Pool ID '{}'", userPoolId);
        }

    }

//    @Override
//    protected boolean shouldNotFilter(HttpServletRequest request) {
//        return !pathMatcher.match("/oidc/**", request.getRequestURI());
//    }

    private Optional<String> extractClientId(HttpServletRequest request) {
        String clientId = request.getParameter("client_id");
        if (clientId != null && !clientId.isBlank()) {
            return Optional.of(clientId);
        }

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.toLowerCase().startsWith("basic ")) {
            try {
                String base64Credentials = header.substring("Basic ".length()).trim();
                byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
                String credentials = new String(credDecoded, StandardCharsets.UTF_8);
                // credentials = username:password
                final String[] values = credentials.split(":", 2);
                if (values.length > 0 && !values[0].isBlank()) {
                    // Basic Auth 的 username 通常就是 Client ID
                    return Optional.of(values[0]);
                }
            } catch (IllegalArgumentException e) {
                logger.warn("Failed to decode Basic Authorization header: " + e.getMessage());

            }
        }

        return Optional.empty();
    }

    private void sendErrorResponse(HttpServletResponse response, HttpStatus status, String description) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("error", "invalid_request");
        errorResponse.put("error_description", description);
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }

    public static String extractPathAfterDomain(String issuer) {
        if (issuer == null || issuer.isEmpty()) {
            return "";
        }

        try {
            URI uri = new URI(issuer);
            String path = uri.getPath();

            if (path != null) {
                return path.startsWith("/") ? path.substring(1) : path;
            }

        } catch (URISyntaxException e) {
            log.error("Issuer URL 格式不正確， issuer = {}", issuer);
            return "";
        }

        return "";
    }
}
