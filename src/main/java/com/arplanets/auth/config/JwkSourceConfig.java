package com.arplanets.auth.config;

import com.arplanets.auth.component.TenantRegistry;
import com.arplanets.auth.model.po.domain.UserPool;
import com.arplanets.auth.repository.UserPoolRepository;
import com.arplanets.auth.service.TenantJwkService;
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

import java.util.List;

/**
 * 從資料庫載入各個 JWKSource
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class JwkSourceConfig {

    private final TenantRegistry componentRegistry;
    private final TenantJwkService tenantJwkService;
    private final UserPoolRepository userPoolRepository;

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        log.info("Initializing JWKSource from database...");
        List<UserPool> userPools = userPoolRepository.findAll();

        userPools.forEach(userPool -> {
            try {
                tenantJwkService.registerUserPoolJwkSet(userPool);
            } catch (Exception e) {
                log.error("Failed to register JWKSet for UserPool ID: {}. Error: {}",
                        userPool.getUserPoolId(), e.getMessage(), e);
                throw new RuntimeException("Failed to load JWKSource from database due to UserPool JWKSet error.", e);
            }
        });

        return new DelegatingJWKSource(componentRegistry);
    }

    private record DelegatingJWKSource(TenantRegistry componentRegistry) implements JWKSource<SecurityContext> {
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
