package com.arplanets.auth.service.persistence.impl;

import com.arplanets.auth.model.po.domain.AccessToken;
import com.arplanets.auth.model.po.domain.RefreshToken;
import com.arplanets.auth.repository.persistence.AccessTokenRepository;
import com.arplanets.auth.repository.persistence.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final AccessTokenRepository accessTokenRepository;

    public void saveTokens(OAuth2Authorization authorization, String oldRefreshToken) {
        if (authorization == null) return;

        String userId = authorization.getPrincipalName();
        String clientId = authorization.getRegisteredClientId();
        String authSessionId = authorization.getId();


        try {
                OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();

                AccessToken finalAccessToken = AccessToken.builder()
                        .accessTokenValue(accessToken.getTokenValue())
                        .userId(userId)
                        .clientId(clientId)
                        .createdAt(accessToken.getIssuedAt())
                        .expiresAt(accessToken.getExpiresAt())
                        .authSessionId(authSessionId)
                        .refreshTokenValue(oldRefreshToken)
                        .build();

                accessTokenRepository.save(finalAccessToken);

        } catch (Exception e) {
            log.warn("Access Token 記錄失敗", e);
        }

        try {

            OAuth2RefreshToken refreshToken = Objects.requireNonNull(authorization.getRefreshToken()).getToken();

            RefreshToken finalRefreshToken = RefreshToken.builder()
                    .refreshTokenValue(refreshToken.getTokenValue())
                    .userId(userId)
                    .clientId(clientId)
                    .createdAt(refreshToken.getIssuedAt())
                    .expiresAt(refreshToken.getExpiresAt())
                    .authSessionId(authSessionId)
                    .build();

            refreshTokenRepository.save(finalRefreshToken);

        } catch (Exception e) {
            log.warn("Refresh Token 記錄失敗", e);
        }

    }

}
