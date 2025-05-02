package com.arplanets.auth.handler;

import com.arplanets.auth.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
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
import java.util.Map;
import java.util.function.Consumer;

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

        if (authentication instanceof OAuth2AccessTokenAuthenticationToken accessTokenAuthentication) {

            // 取得 Access Token
            OAuth2AccessToken accessToken = accessTokenAuthentication.getAccessToken();

            // 取得 Refresh Token
            OAuth2RefreshToken refreshToken = accessTokenAuthentication.getRefreshToken();

            // 取得 舊的 Refresh Token
            String oldRefreshToken = request.getParameter(OAuth2ParameterNames.REFRESH_TOKEN);


            // 紀錄 Token 狀態
            try {
                OAuth2Authorization authorization = authorizationService.findByToken(
                        accessToken.getTokenValue(),
                        OAuth2TokenType.ACCESS_TOKEN
                );
    
                if (authorization != null) {
                    tokenService.saveTokens(authorization, oldRefreshToken);
                }
            } catch (Exception e) {
                log.warn("紀錄 Token 狀態失敗", e);
            }

            // 取得額外參數
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

            OAuth2AccessTokenResponse accessTokenResponse = builder.build();
            ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
            this.accessTokenResponseConverter.write(accessTokenResponse, null, httpResponse);


        } else {
            String var10001 = Authentication.class.getSimpleName();
            log.error("{} must be of type {} but was {}", var10001, OAuth2AccessTokenAuthenticationToken.class.getName(), authentication.getClass().getName());

            OAuth2Error error;
            error = new OAuth2Error("server_error", "Unable to process the access token response.", null);
            throw new OAuth2AuthenticationException(error);
        }

    }

    public void setAccessTokenResponseCustomizer(Consumer<OAuth2AccessTokenAuthenticationContext> accessTokenResponseCustomizer) {
        Assert.notNull(accessTokenResponseCustomizer, "accessTokenResponseCustomizer cannot be null");
        this.accessTokenResponseCustomizer = accessTokenResponseCustomizer;
    }
}
