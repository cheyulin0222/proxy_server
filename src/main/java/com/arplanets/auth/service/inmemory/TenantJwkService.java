package com.arplanets.auth.service.inmemory;

import com.arplanets.auth.repository.inmemory.TenantRepository;
import com.arplanets.auth.model.po.domain.UserPool;
import com.nimbusds.jose.jwk.JWKSet;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.text.ParseException;

@Service
@RequiredArgsConstructor
@Slf4j
public class TenantJwkService {

    private final TenantRepository tenantRepository;

    public void registerUserPoolJwkSet(UserPool userPool) throws Exception {
        String tenantId = userPool.getPoolName();

        if (tenantId == null) {
            String errorMessage = String.format("Could not determine tenant identifier path for UserPool ID: %s", userPool.getUserPoolId());
            log.error(errorMessage);
            throw new IllegalStateException(errorMessage);
        }

        String jwkSetJson = userPool.getJwkSet();
        if (!StringUtils.hasText(jwkSetJson)) {
            String errorMessage = String.format("JWKSet JSON is missing in the database for UserPool ID: %s, Tenant ID: %s", userPool.getUserPoolId(), tenantId);
            log.error(errorMessage);
            throw new IllegalStateException(errorMessage);
        }

        JWKSet jwkSet;
        try {
            jwkSet = JWKSet.parse(jwkSetJson);
        } catch (ParseException e) {
            String errorMessage = String.format("Failed to parse JWKSet JSON for UserPool ID: %s, Tenant ID: %s. Error: %s", userPool.getUserPoolId(), tenantId, e.getMessage());
            log.error(errorMessage, e);
            throw e;
        }

        tenantRepository.register(tenantId, JWKSet.class, jwkSet);
        log.info("Registered JWKSet for Tenant ID: {}", tenantId);
    }
}
