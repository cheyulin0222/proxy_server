package com.arplanets.auth.service.persistence.impl;

import com.arplanets.auth.log.ErrorType;
import com.arplanets.auth.log.Logger;
import com.arplanets.auth.model.TokenInfo;
import com.arplanets.auth.model.po.domain.AccessToken;
import com.arplanets.auth.model.po.domain.RefreshToken;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.util.Objects;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {

    public TokenInfo getTokens(OAuth2Authorization authorization, String oldRefreshToken) {
        Assert.notNull(authorization, "OAuth2Authorization cannot be null");

        String userId = authorization.getPrincipalName();
        String clientId = authorization.getRegisteredClientId();
        String authId = authorization.getId();

        AccessToken finalAccessToken = null;
        RefreshToken finalRefreshToken = null;

        try {
            OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();

            finalAccessToken = AccessToken.builder()
                .accessTokenValue(accessToken.getTokenValue())
                .userId(userId)
                .clientId(clientId)
                .createdAt(accessToken.getIssuedAt())
                .expiresAt(accessToken.getExpiresAt())
                .authId(authId)
                .refreshTokenValue(oldRefreshToken)
                .build();

        } catch (Exception e) {
            Logger.error("Access Token 記錄失敗", ErrorType.SYSTEM, e);
        }

        try {

            OAuth2RefreshToken refreshToken = Objects.requireNonNull(authorization.getRefreshToken()).getToken();

            finalRefreshToken = RefreshToken.builder()
                .refreshTokenValue(refreshToken.getTokenValue())
                .userId(userId)
                .clientId(clientId)
                .createdAt(refreshToken.getIssuedAt())
                .expiresAt(refreshToken.getExpiresAt())
                .authId(authId)
                .build();

        } catch (Exception e) {
            Logger.error("Refresh Token 記錄失敗", ErrorType.SYSTEM, e);
        }

        return TokenInfo.builder()
                .accessToken(finalAccessToken)
                .refreshToken(finalRefreshToken)
                .build();
    }
}
