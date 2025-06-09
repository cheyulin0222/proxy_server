package com.arplanets.auth.filter;

import com.arplanets.auth.model.UserPoolContext;
import com.arplanets.auth.model.UserPoolContextHolder;
import com.arplanets.auth.model.UserPoolInfo;
import com.arplanets.auth.service.inmemory.UserPoolInfoSource;
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
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@Slf4j
public class UserPoolValidationFilter extends OncePerRequestFilter {

    private final UserPoolInfoSource userPoolInfoSource;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {

        AuthorizationServerContext context = AuthorizationServerContextHolder.getContext();
        if (context == null || context.getIssuer() == null) {
            log.warn("Cannot get component, AuthorizationServerContext or Issuer is null.");
            sendErrorResponse(response, HttpStatus.INTERNAL_SERVER_ERROR, "AuthorizationServerContext or Issuer is null.");
            return;
        }

        String issuer = context.getIssuer();

        String poolName = extractPathAfterDomain(issuer);

        if (poolName.isBlank()) {
            log.warn("Pool name not found in issuer : {}", issuer);
            sendErrorResponse(response, HttpStatus.BAD_REQUEST, "Missing or invalid poolName.");
            return;
        }

        UserPoolInfo userPoolInfo = userPoolInfoSource.getUserPoolInfo();

        if (userPoolInfo == null) {
            log.warn("User pool not found for pool name: {}", poolName);
            sendErrorResponse(response, HttpStatus.NOT_FOUND, "User pool not found.");
            return;
        }

        String userPoolId = userPoolInfo.getUserPoolId();
        UserPoolContextHolder.setContext(new UserPoolContext(userPoolId, userPoolInfo));
        log.debug("Set UserPoolContext for User Pool ID '{}'", userPoolId);

        try {
            filterChain.doFilter(request, response);
        } finally {
            UserPoolContextHolder.clearContext();
            log.debug("Cleared UserPoolContext for User Pool ID '{}'", userPoolId);
        }

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
