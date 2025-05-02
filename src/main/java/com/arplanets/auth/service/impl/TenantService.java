package com.arplanets.auth.service.impl;

import com.arplanets.auth.component.TenantPerIssuerComponentRegistry;
import com.arplanets.auth.model.po.domain.UserPool;
import com.arplanets.auth.repository.UserPoolRepository;
import com.nimbusds.jose.jwk.JWKSet;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;

@Service
@RequiredArgsConstructor
@Slf4j
public class TenantService {

    private final TenantPerIssuerComponentRegistry componentRegistry;
    private final UserPoolRepository userPoolRepository;

    public void createTenant(String userPoolId) {
        UserPool userPool = userPoolRepository.findById(userPoolId);
        String tenantId = null;
        try {
            tenantId = determineTenantIdentifierPath(userPool.getPoolName());
            if (tenantId == null) {
                log.error("Could not determine tenant identifier path for UserPool ID: {}", userPool.getUserPoolId());
                return;
            }

            String jwkSetJson = userPool.getJwkSet();
            if (!StringUtils.hasText(jwkSetJson)) {
                log.error("JWKSet JSON is missing in the database for UserPool ID: {}, Tenant ID: {}", userPool.getUserPoolId(), tenantId);
                return;
            }

            JWKSet jwkSet;
            try {
                jwkSet = JWKSet.parse(jwkSetJson);
            } catch (ParseException e) {
                log.error("Failed to parse JWKSet JSON for UserPool ID: {}, Tenant ID: {}. Error: {}", userPool.getUserPoolId(), tenantId, e.getMessage());
                return;
            }

            componentRegistry.register(tenantId, JWKSet.class, jwkSet);
            log.info("Successfully registered JWKSet for Tenant ID: {}", tenantId);


        } catch (IllegalArgumentException e) {
            log.error("Error processing UserPool ID: {}. Invalid configuration: {}", userPool.getUserPoolId(), e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error processing UserPool ID: {}, Tenant ID: {}. Error: {}", userPool.getUserPoolId(), tenantId, e.getMessage(), e);
        }
    }

    private String determineTenantIdentifierPath(String issuer) {
        if (!StringUtils.hasText(issuer)) {
            return null;
        }
        try {
            URI issuerUri = new URI(issuer);
            String path = issuerUri.getPath();
            // 確保路徑不為空且有效（例如，不只是 "/"）
            if (StringUtils.hasText(path) && path.length() > 1) {
                return path;
            } else {
                log.warn("Issuer URI '{}' has an invalid or empty path component.", issuer);
                return null;
            }
        } catch (URISyntaxException e) {
            log.error("Invalid Issuer URI syntax: {}", issuer, e);
            return null;
        }
    }

}
