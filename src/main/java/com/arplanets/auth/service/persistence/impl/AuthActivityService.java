package com.arplanets.auth.service.persistence.impl;

import com.arplanets.auth.log.ErrorType;
import com.arplanets.auth.log.Logger;
import com.arplanets.auth.model.enums.AuthAction;
import com.arplanets.auth.model.po.domain.AuthActivity;
import com.arplanets.auth.test.AuthActivityRepository;
import com.arplanets.auth.utils.ClientInfoUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class AuthActivityService {

    public AuthActivity getAuthActivity(OAuth2Authorization authorization, HttpServletRequest request, AuthAction authAction) {
        AuthActivity authActivity = null;

        try {
            String refreshToken = getTokenValue(authorization.getRefreshToken());
            String accessToken = getTokenValue(authorization.getAccessToken());
            String userId = authorization.getPrincipalName();

            // 獲取發行時間
            Instant issuedAt = getIssuedAt(authorization);

            // 獲取客戶端資訊
            Map<String, String> clientInfo = getClientInfo(request);

            authActivity =  AuthActivity.builder()
                    .authId(authorization.getId())
                    .refreshTokenValue(refreshToken)
                    .accessTokenValue(accessToken)
                    .userId(userId)
                    .action(authAction.name())
                    .ip(ClientInfoUtil.getClientIp(request))
                    .deviceType(clientInfo.get("deviceType"))
                    .osName(clientInfo.get("osName"))
                    .osVersion(clientInfo.get("osVersion"))
                    .createdAt(issuedAt)
                    .build();


        } catch (Exception e) {
            Logger.error("記錄 AuthActivity 時發生錯誤", ErrorType.SYSTEM, e);
        }

        return authActivity;
    }

    public Map<String, Object> getAuthContext(OAuth2Authorization authorization, HttpServletRequest request, AuthAction authAction) {
        AuthActivity authActivity = getAuthActivity(authorization, request, authAction);
        Map<String, Object> context = new HashMap<>();
        context.put("authActivity", authActivity);
        return context;
    }

    private String getTokenValue(OAuth2Authorization.Token<?> token) {
        if (token == null || token.getToken() == null) {
            return null;
        }
        return token.getToken().getTokenValue();
    }

    private Instant getIssuedAt(OAuth2Authorization authorization) {
        try {
            OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                    authorization.getToken(OAuth2AuthorizationCode.class);

            assert authorizationCode != null;
            return authorizationCode.getToken().getIssuedAt();
        } catch (Exception e) {
            log.debug("獲取授權碼發行時間失敗，將使用當前時間", e);
        }

        return null;
    }

    private Map<String, String> getClientInfo(HttpServletRequest request) {
        try {
            return ClientInfoUtil.getClientInfo(request);
        } catch (Exception e) {
            log.warn("解析客戶端資訊失敗", e);
            Map<String, String> defaultInfo = new HashMap<>();
            defaultInfo.put("deviceType", "Unknown");
            defaultInfo.put("osName", "Unknown");
            defaultInfo.put("osVersion", "Unknown");
            return defaultInfo;
        }
    }

}
