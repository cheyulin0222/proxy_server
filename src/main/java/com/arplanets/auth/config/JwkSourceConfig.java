package com.arplanets.auth.config;

import com.arplanets.auth.repository.inmemory.TenantRepository;
import com.arplanets.auth.model.po.domain.UserPool;
import com.arplanets.auth.repository.persistence.UserPoolRepository;
import com.arplanets.auth.service.inmemory.TenantJwkService;
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

    private final TenantRepository tenantRepository;
    private final TenantJwkService tenantJwkService;
    private final UserPoolRepository userPoolRepository;

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        log.info("Starting to load JWKSource...");

        try {
            // 查詢所有 User Pools
            List<UserPool> userPools = userPoolRepository.findAll();
            if (userPools == null || userPools.isEmpty()) {
                log.error("No user pools found in the database.");
                throw new RuntimeException("No user pools found in the database.");
            }

            // 註冊 JWKSets 到應用程式
            userPools.forEach(userPool -> {
                try {
                    tenantJwkService.registerUserPoolJwkSet(userPool);
                } catch (Exception e) {
                    log.error("Failed to register JWKSet for UserPool ID: {}. Error: {}",
                            userPool.getUserPoolId(), e.getMessage(), e);
                    throw new RuntimeException(e);
                }
            });

            log.info("Successfully loaded {} JWKSets.", userPools.size());

            return new DelegatingJWKSource(tenantRepository);
        } catch (Exception e) {
            log.error("Failed to load JWKSource: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to load JWKSource");
        }
    }

    private record DelegatingJWKSource(TenantRepository componentRegistry) implements JWKSource<SecurityContext> {
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
