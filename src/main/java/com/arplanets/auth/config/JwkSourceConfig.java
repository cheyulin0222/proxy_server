package com.arplanets.auth.config;

import com.arplanets.auth.component.TenantPerIssuerComponentRegistry;
import com.arplanets.auth.model.po.domain.UserPool;
import com.arplanets.auth.repository.UserPoolRepository;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;

@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
@Slf4j
public class JwkSourceConfig {

    private final TenantPerIssuerComponentRegistry componentRegistry;
    private final UserPoolRepository userPoolRepository;

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        log.info("Initializing JWKSource from database...");
        List<UserPool> userPools = userPoolRepository.findAll();
        log.info("Found {} user pools in the database.", userPools.size());

        userPools.forEach(userPool -> {
            String tenantId = null;
            try {
                tenantId = userPool.getPoolName();
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

        });

        return new DelegatingJWKSource(componentRegistry);
    }


    private String determineTenantIdentifierPath(String issuer) {
        if (!StringUtils.hasText(issuer)) {
            return null;
        }
        try {
            URI issuerUri = new URI(issuer);
            String path = issuerUri.getPath();
            log.info("path = {}", path);
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

    @RequiredArgsConstructor
    private static class DelegatingJWKSource implements JWKSource<SecurityContext> {
        private final TenantPerIssuerComponentRegistry componentRegistry;

        @Override
        public List<JWK> get(JWKSelector jwkSelector, SecurityContext securityContext) throws KeySourceException {
            // 從註冊表獲取當前租戶的 JWKSet
            JWKSet tenantJwkSet = this.componentRegistry.get(JWKSet.class);

            // 如果找不到該租戶的 JWKSet，則拋出異常或返回空列表
            Assert.state(tenantJwkSet != null, "JWKSet not found for the current issuer. Ensure the tenant is registered.");

            // 使用獲取到的租戶 JWKSet 進行密鑰選擇
            List<JWK> jwks = jwkSelector.select(tenantJwkSet);

            jwks.forEach(jwk -> {
                log.info("jwk={}", jwk.toString());
            });

            return jwkSelector.select(tenantJwkSet);
        }
    }




    // 輔助方法：生成 RSA 密鑰對並包裝為 RSAKey
    private static RSAKey generateRsaKey(String keyId) {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(keyId) // 為密鑰指定一個 ID
                .build();
    }
}
