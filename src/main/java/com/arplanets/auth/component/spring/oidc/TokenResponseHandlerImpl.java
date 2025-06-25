package com.arplanets.auth.component.spring.oidc;

import com.arplanets.auth.log.ErrorType;
import com.arplanets.auth.log.Logger;
import com.arplanets.auth.model.TokenInfo;
import com.arplanets.auth.service.persistence.impl.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.io.IOException;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * 紀錄 Token 交換資訊
 */
@RequiredArgsConstructor
@Slf4j
public class TokenResponseHandlerImpl implements AuthenticationSuccessHandler {


    private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenResponseConverter =
            new OAuth2AccessTokenResponseHttpMessageConverter();

    private final TokenService tokenService;
    private final OAuth2AuthorizationService authorizationService;
    private Consumer<OAuth2AccessTokenAuthenticationContext> accessTokenResponseCustomizer;


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        try {
            if (authentication instanceof OAuth2AccessTokenAuthenticationToken accessTokenAuthentication) {
                    // 取得 Access Token
                    OAuth2AccessToken accessToken = accessTokenAuthentication.getAccessToken();

                    // 取得 Refresh Token
                    OAuth2RefreshToken refreshToken = accessTokenAuthentication.getRefreshToken();

                    // 取得 舊的 Refresh Token
                    String oldRefreshToken = request.getParameter(OAuth2ParameterNames.REFRESH_TOKEN);

                    OAuth2AccessTokenResponse accessTokenResponse = buildTokenResponse(accessTokenAuthentication, accessToken, refreshToken);

                    ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
                    this.accessTokenResponseConverter.write(accessTokenResponse, null, httpResponse);

                    // 紀錄 Token 狀態
                    loggingTokenInfo(accessToken, oldRefreshToken);
            } else {
                String var10001 = Authentication.class.getSimpleName();
                String errorString = var10001 + " must be of type " + OAuth2AccessTokenAuthenticationToken.class.getName() + " but was " + authentication.getClass().getName();

                throw new RuntimeException(errorString);
            }
        } catch (Exception e) {
            Logger.error("token.exchange.failed", ErrorType.SYSTEM, e);
            throw new IOException("Unable to process the access token response.");
        }

    }

    public void setAccessTokenResponseCustomizer(Consumer<OAuth2AccessTokenAuthenticationContext> accessTokenResponseCustomizer) {
        Assert.notNull(accessTokenResponseCustomizer, "accessTokenResponseCustomizer cannot be null");
        this.accessTokenResponseCustomizer = accessTokenResponseCustomizer;
    }

    private HashMap<String, Object> getContext(TokenInfo tokenInfo) {
        HashMap<String, Object> context = new HashMap<>();
        context.put("tokenInfo", tokenInfo);
        return context;
    }

    private void loggingTokenInfo(OAuth2AccessToken accessToken, String oldRefreshToken) {
        try {
            OAuth2Authorization authorization = authorizationService.findByToken(
                    accessToken.getTokenValue(),
                    OAuth2TokenType.ACCESS_TOKEN
            );

            TokenInfo tokenInfo = tokenService.getTokens(authorization, oldRefreshToken);

            Logger.info("token.exchange.success", getContext(tokenInfo));
        } catch (Exception e) {
            Logger.error("紀錄 Token 狀態失敗", ErrorType.SYSTEM, e);
        }
    }

    private OAuth2AccessTokenResponse buildTokenResponse(OAuth2AccessTokenAuthenticationToken accessTokenAuthentication, OAuth2AccessToken accessToken, OAuth2RefreshToken refreshToken) {
        Map<String, Object> additionalParameters = accessTokenAuthentication.getAdditionalParameters();


        // 建立 Response
        OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse
                // access_token
                .withToken(accessToken.getTokenValue())
                // token_type (Bearer)
                .tokenType(accessToken.getTokenType())
                // scope
                .scopes(accessToken.getScopes());

        // expires_in
        if (accessToken.getIssuedAt() != null && accessToken.getExpiresAt() != null) {
            builder.expiresIn(ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()));
        }

        // refresh_token
        if (refreshToken != null) {
            builder.refreshToken(refreshToken.getTokenValue());
        }

        // 添加額外屬性
        if (!CollectionUtils.isEmpty(additionalParameters)) {
            builder.additionalParameters(additionalParameters);
        }

        // 添加客製化屬性
        if (this.accessTokenResponseCustomizer != null) {
            OAuth2AccessTokenAuthenticationContext accessTokenAuthenticationContext = OAuth2AccessTokenAuthenticationContext.with(accessTokenAuthentication).accessTokenResponse(builder).build();
            this.accessTokenResponseCustomizer.accept(accessTokenAuthenticationContext);
            log.trace("Customized access token response");
        }

        return builder.build();

    }
}
