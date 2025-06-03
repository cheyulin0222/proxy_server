package com.arplanets.auth.service.impl;

import com.arplanets.auth.component.TenantRegistry;
import com.arplanets.auth.model.UserPoolInfo;
import com.arplanets.auth.model.po.domain.UserPool;
import com.arplanets.auth.service.UserPoolInfoService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserPoolInfoServiceImpl implements UserPoolInfoService {

    private final TenantRegistry tenantRegistry;

    @Override
    public void registerUserPoolInfo(UserPool userPool) throws Exception {
        try {
            validate(userPool);
            UserPoolInfo userPoolInfo = UserPoolInfo.builder()
                    .userPoolId(userPool.getUserPoolId())
                    .poolName(userPool.getPoolName())
                    .build();
            this.tenantRegistry.register(userPool.getPoolName(), UserPoolInfo.class, userPoolInfo);
            log.info("Registered UserPoolInfo for Tenant ID: {}", userPool.getPoolName());
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    @Override
    public UserPoolInfo findByPoolId(String poolId) {
        return tenantRegistry.getAll(UserPoolInfo.class).stream()
                .filter(userPoolInfo -> userPoolInfo.getUserPoolId().equals(poolId))
                .findFirst()
                .orElse(null);
    }

    @Override
    public UserPoolInfo findByPoolName(String poolName) {
        return tenantRegistry.get(UserPoolInfo.class, poolName);
    }


    private void validate(UserPool userPool) {
        if (userPool == null) {
            throw new IllegalArgumentException("userPool 不能為空");
        }
        validateField(userPool.getUserPoolId(), "user_pool_id");
        validateField(userPool.getPoolName(), "user_pool_name");
    }

    private void validateField(String value, String fieldName) {
        if (!StringUtils.hasText(value)) {
            log.error("{} 不能為空", fieldName);
            throw new IllegalArgumentException(fieldName + " 不能為空");
        }
        log.info("{}: {}", fieldName, value);
    }
}
