package com.arplanets.auth.component.spring.oidc;

import com.arplanets.auth.utils.StringUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
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

    @Override
    public void customize(JwtEncodingContext context) {

        // 獲取當前認證信息，供不同 Token 類型共享
        Authentication authentication = context.getPrincipal();

        // 判斷是 Access Token 還是REFRESH TOKEN 還是 ID Token
        boolean isAccessToken = OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType());
        boolean isRefreshToken = OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType());
        boolean isIdToken = context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN);

        if (isAccessToken) {
            // 添加 ACCESS_TOKEN 邏輯
            customizeAccessToken(context, authentication);
        } else if (isIdToken) {
            // 添加 ID_TOKEN 邏輯
            customizeIdToken(context, authentication);
        } else if (isRefreshToken) {
            // 添加 REFRESH_TOKEN 邏輯
            customizeRefreshToken(context, authentication);
        }
    }

    private void customizeAccessToken(JwtEncodingContext context, Authentication authentication) {
        if (authentication == null) {
            return;
        }
        if (context.getAuthorization() != null) {
            // 添加 registration_id
            if (authentication instanceof OAuth2AuthenticationToken oauth2Token) {
                if (oauth2Token.getAuthorizedClientRegistrationId() != null) {
                    context.getClaims().claim(StringUtil.REGISTRATION_ID_ATTRIBUTE_NAME, oauth2Token.getAuthorizedClientRegistrationId());
                }
            }

            // 添加 auth_id
            if (context.getAuthorization().getId() != null) {
                context.getClaims().claim(StringUtil.AUTH_ID, context.getAuthorization().getId());
            }
        }
    }

    private void customizeIdToken(JwtEncodingContext context, Authentication authentication) {
        if (authentication == null) {
            return;
        }
        String sessionId = null;

        if (context.getAuthorization() != null) {
            sessionId = context.getAuthorization().getAttribute(StringUtil.AUTH_SESSION_ID);
        }


        // 添加 sid
        if (sessionId != null) {
            try {
                String sessionHash = createHash(sessionId);
                context.getClaims().claim(StringUtil.SID_CLAIM_NAME, sessionHash);
            } catch (NoSuchAlgorithmException e) {
                log.error("Failed to compute hash for Session ID: {}", e.getMessage());
            }
        }

    }

    private void customizeRefreshToken(JwtEncodingContext context, Authentication authentication) {
    }

    private String createHash(String value) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(value.getBytes());
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
