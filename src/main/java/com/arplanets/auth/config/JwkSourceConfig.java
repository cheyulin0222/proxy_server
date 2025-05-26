package com.arplanets.auth.config;

import com.arplanets.auth.component.TenantPerIssuerComponentRegistry;
import com.arplanets.auth.model.po.domain.UserPool;
import com.arplanets.auth.repository.UserPoolRepository;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.text.ParseException;
import java.util.List;

/**
 * 從資料庫載入各個 JWKSource
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class JwkSourceConfig {

    private final TenantPerIssuerComponentRegistry componentRegistry;
    private final UserPoolRepository userPoolRepository;

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        log.info("Initializing JWKSource from database...");
        List<UserPool> userPools = userPoolRepository.findAll();

        userPools.forEach(userPool -> {
            String tenantId = null;
            try {
                tenantId = userPool.getPoolName();
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
                    throw new IllegalStateException(errorMessage, e);
                }

                componentRegistry.register(tenantId, JWKSet.class, jwkSet);
                log.info("Successfully registered JWKSet for Tenant ID: {}", tenantId);


            } catch (IllegalArgumentException e) {
                String errorMessage = String.format("Error processing UserPool ID: %s. Invalid configuration: %s", userPool.getUserPoolId(), e.getMessage());
                log.error(errorMessage, e);
                throw new IllegalStateException(errorMessage, e);
            } catch (Exception e) {
                String errorMessage = String.format("Unexpected error processing UserPool ID: %s, Tenant ID: %s. Error: %s", userPool.getUserPoolId(), tenantId, e.getMessage());
                log.error(errorMessage, e);
                throw new RuntimeException(errorMessage, e);
            }
        });

        return new DelegatingJWKSource(componentRegistry);
    }

    private record DelegatingJWKSource(TenantPerIssuerComponentRegistry componentRegistry) implements JWKSource<SecurityContext> {
        @Override
        public List<JWK> get(JWKSelector jwkSelector, SecurityContext securityContext) {
            // 從註冊表獲取當前租戶的 JWKSet
            JWKSet tenantJwkSet = this.componentRegistry.get(JWKSet.class);

            // 如果找不到該租戶的 JWKSet，則拋出異常或返回空列表
            Assert.state(tenantJwkSet != null, "JWKSet not found for the current issuer. Ensure the tenant is registered.");

            return jwkSelector.select(tenantJwkSet);
        }
    }

}
