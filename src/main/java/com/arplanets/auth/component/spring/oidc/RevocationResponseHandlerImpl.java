package com.arplanets.auth.component.spring.oidc;

import com.arplanets.auth.log.ErrorType;
import com.arplanets.auth.log.Logger;
import com.arplanets.auth.model.po.domain.RevocationToken;
import com.arplanets.auth.utils.StringUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class RevocationResponseHandlerImpl implements AuthenticationSuccessHandler {

    private final OAuth2AuthorizationService oAuth2AuthorizationService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        response.setStatus(HttpStatus.OK.value());
        try {
            logRevokedTokenInfo(request, authentication);
        } catch (Exception e) {
            Logger.error("紀錄 Token Revocation 失敗", ErrorType.SYSTEM, e);
        }
    }

    private void logRevokedTokenInfo(HttpServletRequest request, Authentication authentication) {
        if (authentication instanceof OAuth2TokenRevocationAuthenticationToken revocationAuthenticationToken) {
            String tokenValue = getTokenValue(revocationAuthenticationToken);
            String clientId = getClientId(revocationAuthenticationToken);
            String tokenType = getTokenType(request);

            OAuth2Authorization authorization = getAuthorization(tokenValue, tokenType);

            String authId = getAuthId(authorization);
            String userId = getUserId(authorization);
            Instant createdAt = getCreatedAt(authorization, tokenType);
            Instant expiresAt = getExpiresAt(authorization, tokenType);

            RevocationToken revokedTokenInfo = RevocationToken.builder()
                    .authId(authId)
                    .tokenValue(tokenValue)
                    .tokenType(tokenType)
                    .userId(userId)
                    .clientId(clientId)
                    .createdAt(createdAt)
                    .expiresAt(expiresAt)
                    .revokedAt(Instant.now())
                    .build();

            Logger.info("revoke.success", getContext(revokedTokenInfo));
        } else {
            throw new RuntimeException("無法獲取OAuth2TokenRevocationAuthenticationToken");
        }

    }

    private String getTokenValue(OAuth2TokenRevocationAuthenticationToken revocationAuthenticationToken) {
        return revocationAuthenticationToken.getToken();
    }

    private String getClientId(OAuth2TokenRevocationAuthenticationToken revocationAuthenticationToken) {
        if (revocationAuthenticationToken.getPrincipal() instanceof OAuth2ClientAuthenticationToken clientAuthentication) {
            if (clientAuthentication.getRegisteredClient() != null) {
                return clientAuthentication.getRegisteredClient().getClientId();
            }
        }
        return null;
    }

    private String getTokenType(HttpServletRequest request) {
        return request.getParameter(StringUtil.TOKEN_TYPE_HINT_PARAM_NAME);
    }

    private OAuth2Authorization getAuthorization(String tokenValue, String tokenType) {
        OAuth2Authorization authorization = null;
        try {
            authorization = oAuth2AuthorizationService.findByToken(tokenValue, new OAuth2TokenType(tokenType));
        } catch (UnsupportedOperationException e) {
            Logger.warn("OAuth2AuthorizationService 不支持透過 tokenValue 和 tokenType 查詢，部分 Token 資訊可能缺失。");
        }
        return authorization;
    }

    private Map<String, Object> getContext(RevocationToken revokedTokenInfo) {
        Map<String, Object> context = new HashMap<>();
        context.put("revocationInfo", revokedTokenInfo);
        return context;
    }

    private String getAuthId(OAuth2Authorization authorization) {
        return authorization != null ? authorization.getId() : null;
    }

    private String getUserId(OAuth2Authorization authorization) {
        return authorization != null ? authorization.getPrincipalName() : null;
    }

    private Instant getCreatedAt(OAuth2Authorization authorization, String tokenType) {
        if (authorization == null) return null;

        if (StringUtil.ACCESS_TOKEN_PARAM_NAME.equals(tokenType)) {
            OAuth2Authorization.Token<OAuth2AccessToken> accessTokenEntry = authorization.getAccessToken();
            if (accessTokenEntry != null && accessTokenEntry.getToken() != null) {
                return accessTokenEntry.getToken().getIssuedAt();
            }
        } else if (StringUtil.REFRESH_TOKEN_PARAM_NAME.equals(tokenType)) {
            OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenEntry = authorization.getRefreshToken();
            if (refreshTokenEntry != null && refreshTokenEntry.getToken() != null) {
                return refreshTokenEntry.getToken().getIssuedAt();
            }
        } else if (StringUtil.ID_TOKEN_PARAM_NAME.equals(tokenType)) {
            OAuth2Authorization.Token<OidcIdToken> idTokenEntry = authorization.getToken(OidcIdToken.class);
            if (idTokenEntry != null && idTokenEntry.getToken() != null) {
                return idTokenEntry.getToken().getIssuedAt();
            }
        }

        return null;
    }

    private Instant getExpiresAt(OAuth2Authorization authorization, String tokenType) {
        if (authorization == null) return null;

        if (StringUtil.ACCESS_TOKEN_PARAM_NAME.equals(tokenType)) {
            OAuth2Authorization.Token<OAuth2AccessToken> accessTokenEntry = authorization.getAccessToken();
            if (accessTokenEntry != null && accessTokenEntry.getToken() != null) {
                return accessTokenEntry.getToken().getExpiresAt();
            }
        } else if (StringUtil.REFRESH_TOKEN_PARAM_NAME.equals(tokenType)) {
            OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenEntry = authorization.getRefreshToken();
            if (refreshTokenEntry != null && refreshTokenEntry.getToken() != null) {
                return refreshTokenEntry.getToken().getExpiresAt();
            }
        } else if (StringUtil.ID_TOKEN_PARAM_NAME.equals(tokenType)) {
            OAuth2Authorization.Token<OidcIdToken> idTokenEntry = authorization.getToken(OidcIdToken.class);
            if (idTokenEntry != null && idTokenEntry.getToken() != null) {
                return idTokenEntry.getToken().getExpiresAt();
            }
        }

        return null;
    }
}
