package com.arplanets.auth.service.inmemory;

import com.arplanets.auth.repository.inmemory.TenantRepository;
import com.arplanets.auth.model.UserPoolInfo;
import com.arplanets.auth.model.po.domain.UserPool;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * 查詢、註冊、移除 In-memory User Pool Info
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserPoolInfoService {

    private final TenantRepository tenantRepository;

    public void registerUserPoolInfo(UserPool userPool) {
        // 檢核資料
        validate(userPool);

        // 註冊 User Pool Info
        UserPoolInfo userPoolInfo = UserPoolInfo.builder()
                .userPoolId(userPool.getUserPoolId())
                .poolName(userPool.getPoolName())
                .build();
        this.tenantRepository.register(userPool.getPoolName(), UserPoolInfo.class, userPoolInfo);

        log.info("Registered UserPoolInfo for Tenant ID: '{}'. User Pool ID '{}'. User Pool Name '{}'",
                userPool.getPoolName(),
                userPoolInfo.getUserPoolId(),
                userPoolInfo.getPoolName());
    }

    public UserPoolInfo findByPoolId(String poolId) {
        return tenantRepository.getAll(UserPoolInfo.class).stream()
                .filter(userPoolInfo -> userPoolInfo.getUserPoolId().equals(poolId))
                .findFirst()
                .orElse(null);
    }

    public UserPoolInfo findByPoolName(String poolName) {
        return tenantRepository.get(UserPoolInfo.class, poolName);
    }

    private void validate(UserPool userPool) {
        if (userPool == null) {
            log.error("userPool 不能為空");
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
    }
}
