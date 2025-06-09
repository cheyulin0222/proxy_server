package com.arplanets.auth.config;

import com.arplanets.auth.repository.inmemory.TenantRepository;
import com.arplanets.auth.model.UserPoolInfo;
import com.arplanets.auth.model.po.domain.UserPool;
import com.arplanets.auth.repository.persistence.UserPoolRepository;
import com.arplanets.auth.service.inmemory.UserPoolInfoService;
import com.arplanets.auth.service.inmemory.UserPoolInfoSource;
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

    private final TenantRepository tenantRepository;
    private final UserPoolRepository userPoolRepository;
    private final UserPoolInfoService userPoolInfoService;

    @Bean
    public UserPoolInfoSource userPoolInfoSource() {
        log.info("Starting to load userPoolInfos...");

        try {
            // 查詢所有 User Pools
            List<UserPool> userPools = userPoolRepository.findAll();
            if (userPools == null || userPools.isEmpty()) {
                log.error("No user pools found in the database.");
                throw new RuntimeException("No user pools found in the database.");
            }

            // 註冊 User Pool Infos 到應用程式
            userPools.forEach(userPool -> {
                try {
                    userPoolInfoService.registerUserPoolInfo(userPool);
                } catch (Exception e) {
                    log.error("Failed to register User Pool: {}", e.getMessage(), e);
                    throw new RuntimeException("Failed to load UserPools", e);
                }
            });

            log.info("Successfully loaded {} userPoolInfos.", userPools.size());

            return new DelegatingUserPoolInfoSource(tenantRepository);
        } catch (Exception e) {
            log.error("Failed to load userPoolInfo: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to load userPoolInfo");
        }
    }

    private record DelegatingUserPoolInfoSource(TenantRepository tenantRepository) implements UserPoolInfoSource {
        @Override
        public UserPoolInfo getUserPoolInfo() {
            UserPoolInfo userPoolInfo = this.tenantRepository.get(UserPoolInfo.class);

            if (userPoolInfo == null || !StringUtils.hasText(userPoolInfo.getUserPoolId()) || !StringUtils.hasText(userPoolInfo.getPoolName())) {
                log.error("UserPoolInfo not found or invalid for the issuer. Ensure the tenant is registered correctly.");
            }
            return userPoolInfo;
        }
    }
}
