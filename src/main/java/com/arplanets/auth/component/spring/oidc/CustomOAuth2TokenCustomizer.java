package com.arplanets.auth.component.spring.oidc;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;



@Component
@Slf4j
public class CustomOAuth2TokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {

        // 判斷是 Access Token 還是REFRESH TOKEN 還是 ID Token
        boolean isAccessToken = OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType());
        boolean isRefreshToken = OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType());
        boolean isIdToken = context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN);

        if (isAccessToken || isIdToken || isRefreshToken) {
            // 添加共同邏輯

            if (isAccessToken) {
                // 添加 ACCESS_TOKEN 邏輯

                if (context.getAuthorization() != null) {

                    // 添加 registration_id
                    Authentication authentication = context.getPrincipal();

                    if (authentication instanceof OAuth2AuthenticationToken oauth2Token) {
                        if (oauth2Token.getAuthorizedClientRegistrationId() != null) {
                            context.getClaims().claim("registration_id", oauth2Token.getAuthorizedClientRegistrationId());
                        }
                    }

                    // 添加 auth_session_id
                    if (context.getAuthorization().getId() != null) {
                        context.getClaims().claim("auth_session_id", context.getAuthorization().getId());
                    }
                }
            } else if (isRefreshToken) {
                // 添加 REFRESH_TOKEN 邏輯
            } else if (isIdToken) {
                // 添加 ID_TOKEN 邏輯
            }
        }
    }
}
