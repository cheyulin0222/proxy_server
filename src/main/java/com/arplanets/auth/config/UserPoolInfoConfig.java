package com.arplanets.auth.config;

import com.arplanets.auth.component.TenantRegistry;
import com.arplanets.auth.model.UserPoolInfo;
import com.arplanets.auth.model.po.domain.UserPool;
import com.arplanets.auth.repository.UserPoolRepository;
import com.arplanets.auth.service.UserPoolInfoService;
import com.arplanets.auth.service.UserPoolInfoSource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import java.util.List;

/**
 * 從資料庫載入各個 UserPool
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class UserPoolInfoConfig {

    private final TenantRegistry tenantRegistry;
    private final UserPoolRepository userPoolRepository;
    private final UserPoolInfoService userPoolInfoService;

    @Bean
    public UserPoolInfoSource userPoolInfoSource() {
        log.info("Load UserPools...");
        List<UserPool> userPools = userPoolRepository.findAll();
        userPools.forEach(userPool -> {
            try {
                userPoolInfoService.registerUserPoolInfo(userPool);
            } catch (Exception e) {
                log.error("Failed to register User Pool: {}", e.getMessage(), e);
                throw new RuntimeException("Failed to load UserPools", e);
            }
        });

        return new DelegatingUserPoolInfoSource(tenantRegistry);
    }

    private record DelegatingUserPoolInfoSource(TenantRegistry tenantRegistry) implements UserPoolInfoSource {

        @Override
        public UserPoolInfo getUserPoolInfo() {
            UserPoolInfo userPoolInfo = this.tenantRegistry.get(UserPoolInfo.class);
            log.info("userPoolInfo={}", userPoolInfo);

            if (userPoolInfo != null) {
                log.info("userPoolId={}", userPoolInfo.getUserPoolId());
                log.info("poolName={}", userPoolInfo.getPoolName());
            }

            if (userPoolInfo == null || !StringUtils.hasText(userPoolInfo.getUserPoolId()) || !StringUtils.hasText(userPoolInfo.getPoolName())) {
                log.error("UserPoolInfo not found or invalid for the issuer. Ensure the tenant is registered correctly.");
            }
            return userPoolInfo;
        }
    }
}
