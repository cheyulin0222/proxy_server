package com.arplanets.auth.repository.inmemory;

import com.arplanets.auth.model.LogoutRequestAttributes;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class LogoutStateRepository {

    private final Map<String, LogoutRequestAttributes> logoutStates = new ConcurrentHashMap<>();
    private static final long DEFAULT_EXPIRES_IN_SECONDS = 300; // 預設 5 分鐘

    public LogoutStateRepository() {
        // 每隔 1 分鐘清理一次過期條目
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(this::cleanupExpiredStates, 1, 1, TimeUnit.MINUTES);
    }

    public String saveLogoutRequest(String postLogoutRedirectUri) {
        Assert.hasText(postLogoutRedirectUri, "postLogoutRedirectUri cannot be empty");

        String state = UUID.randomUUID().toString();
        LogoutRequestAttributes attributes = new LogoutRequestAttributes(postLogoutRedirectUri, DEFAULT_EXPIRES_IN_SECONDS);
        logoutStates.put(state, attributes);

        return state;
    }

    public LogoutRequestAttributes removeLogoutState(String state) {
        Assert.hasText(state, "state cannot be empty");

        // 原子地嘗試獲取並移除條目
        LogoutRequestAttributes retrievedAttributes = logoutStates.remove(state);

        // 不存在
        if (retrievedAttributes == null) {
            log.warn("Warning: Received a state that is not found or has been used/expired");
            return null;
        }

        // 過期
        if (retrievedAttributes.isExpired()) {
            log.warn("Warning: Received a state that was found but expired");
            return null;
        }

        return retrievedAttributes;
    }

    // 定時清理方法
    private void cleanupExpiredStates() {
        logoutStates.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }



}
