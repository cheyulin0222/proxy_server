package com.arplanets.auth.component.spring.oidc;

import com.arplanets.auth.utils.StringUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


/**
 * 客製化 Token
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2TokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final ClientRegistrationRepository clientRegistrationRepository;

    @Override
    public void customize(JwtEncodingContext context) {

        // 獲取當前認證信息，供不同 Token 類型共享
        Authentication authentication = context.getPrincipal();
        OAuth2Authorization authorization = context.getAuthorization();

        // 核心改動：如果 authentication 不是 OAuth2AuthenticationToken 類型，或者 authorization 為 null，
        // 則直接返回，因為後續邏輯主要依賴這些資訊
        if (!(authentication instanceof OAuth2AuthenticationToken oauth2Token) || authorization == null) {
            // log.debug("Authentication is not OAuth2AuthenticationToken or Authorization is null. Skipping token customization.");
            return;
        }

        // 判斷是 Access Token 還是REFRESH TOKEN 還是 ID Token
        boolean isAccessToken = OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType());
        boolean isRefreshToken = OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType());
        boolean isIdToken = context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN);

        if (isAccessToken) {
            // 添加 ACCESS_TOKEN 邏輯
            customizeAccessToken(context, oauth2Token, authorization);
        } else if (isIdToken) {
            // 添加 ID_TOKEN 邏輯
            customizeIdToken(context, oauth2Token, authorization);
        } else if (isRefreshToken) {
            // 添加 REFRESH_TOKEN 邏輯
            customizeRefreshToken(context, oauth2Token, authorization);
        }
    }

    private void customizeAccessToken(JwtEncodingContext context, OAuth2AuthenticationToken oauth2Token, OAuth2Authorization authorization) {
        // 添加 registration_id 、 uuid
        if (oauth2Token.getAuthorizedClientRegistrationId() != null) {
            String registrationId = oauth2Token.getAuthorizedClientRegistrationId();

            // 添加 uuid
            String uuid = getUuid(oauth2Token, registrationId);
            if (uuid != null) {
                context.getClaims().claim(StringUtil.UUID_CLAIM_NAME, uuid);
            }

            // 添加 registration_id
            context.getClaims().claim(StringUtil.REGISTRATION_ID_ATTRIBUTE_NAME, oauth2Token.getAuthorizedClientRegistrationId());
        }

        // 添加 auth_id
        if (authorization.getId() != null) {
            context.getClaims().claim(StringUtil.AUTH_ID, authorization.getId());
        }
    }

    private void customizeIdToken(JwtEncodingContext context, OAuth2AuthenticationToken oauth2Token, OAuth2Authorization authorization) {
        // 添加 uuid
        if (oauth2Token.getAuthorizedClientRegistrationId() != null) {
            String registrationId = oauth2Token.getAuthorizedClientRegistrationId();

            String uuid = getUuid(oauth2Token, registrationId);
            if (uuid != null) {
                context.getClaims().claim(StringUtil.UUID_CLAIM_NAME, uuid);
            }
        }

        // 添加 sid
        String sessionId = authorization.getAttribute(StringUtil.AUTH_SESSION_ID);
        if (sessionId != null) {
            try {
                String sessionHash = createHash(sessionId);
                context.getClaims().claim(StringUtil.SID_CLAIM_NAME, sessionHash);
            } catch (NoSuchAlgorithmException e) {
                log.error("Failed to compute hash for Session ID: {}", e.getMessage());
            }
        }
    }

    private void customizeRefreshToken(JwtEncodingContext context, OAuth2AuthenticationToken oauth2Token, OAuth2Authorization authorization) {
    }

    private String createHash(String value) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(value.getBytes());
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private String getUuid(OAuth2AuthenticationToken oauth2Token, String registrationId) {
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId);

        if (clientRegistration != null && oauth2Token.getPrincipal() instanceof OidcUser oidcUser) {
            return clientRegistration.getClientName() + "_" + oidcUser.getSubject();
        }

        return null;
    }
}
