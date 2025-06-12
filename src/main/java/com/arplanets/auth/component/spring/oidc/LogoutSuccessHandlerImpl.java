package com.arplanets.auth.component.spring.oidc;

import com.arplanets.auth.model.enums.AuthAction;
import com.arplanets.auth.service.persistence.impl.AuthActivityService;
import com.arplanets.auth.repository.inmemory.LogoutStateRepository;
import com.arplanets.auth.service.ProviderLogoutService;
import com.arplanets.auth.utils.StringUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Map;
import java.util.Objects;

/**
 * 紀錄登出資訊
 */
@RequiredArgsConstructor
@Slf4j
public class LogoutSuccessHandlerImpl implements AuthenticationSuccessHandler {

    private final AuthActivityService authActivityService;
    private final OAuth2AuthorizationService authorizationService;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final LogoutStateRepository logoutStateRepository;
    private final ProviderLogoutService providerLogoutService;

    private final LogoutHandler logoutHandler = new SecurityContextLogoutHandler() {{
        setInvalidateHttpSession(true);
    }};
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OidcLogoutAuthenticationToken oidcLogoutAuthentication = (OidcLogoutAuthenticationToken) authentication;

        if (oidcLogoutAuthentication.getSessionId() != null) {
            // 清除本地 Session 和 Security Context
            logoutHandler.logout(request, response, (Authentication) oidcLogoutAuthentication.getPrincipal());

            // 取得授權資料
            OAuth2Authorization authorization = getOAuth2Authorization(oidcLogoutAuthentication);

            // 清理授權數據，紀錄登出活動
            logLogoutActivityAndRemoveAuthorization(request, authorization);

            // 嘗試發起對上游 OIDC Provider 的登出
            // 失敗則直接導回 Client Endpoint
            redirect(request, response, oidcLogoutAuthentication, authorization);

        } else {
            log.warn("Cannot find SessionId to logout.");
            redirectToClientOrDefault(oidcLogoutAuthentication, request, response);
        }
    }

    /**
     * 對上游 OIDC Provider 的登出
     */
    private void redirect(HttpServletRequest request, HttpServletResponse response, OidcLogoutAuthenticationToken oidcLogoutAuthentication, OAuth2Authorization authorization) throws ServletException, IOException {

        try {
            // 取得 redirectUri
            String redirectUri = getRedirectUri(oidcLogoutAuthentication);

            // 生成 state 並儲存到 Local
            String state = logoutStateRepository.saveLogoutRequest(redirectUri);

            // 取得 ClientRegistrationId
            String clientRegistrationId = getClientRegistrationId(authorization);

            // 取得 Provider Session Endpoint
            String endSessionEndpoint = getProviderEndSessionEndpoint(clientRegistrationId);

            // 取得 Provider ID Token
            String providerIdToken = getProviderIdToken(authorization);

            // 構建重定向到你應用程式的回調 URL，並帶上 state
            String providerPostLogoutRedirectUri = UriComponentsBuilder.fromUriString(request.getRequestURL().toString())
                    .replacePath(StringUtil.LOGOUT_CALLBACK_PATH)
                    .queryParam(StringUtil.STATE, state)
                    .build().toUriString();

            // 重定向到上游 OIDC Provider
            providerLogoutService.initiateLogout(
                    endSessionEndpoint,
                    providerIdToken,
                    providerPostLogoutRedirectUri,
                    request,
                    response);
        } catch (Exception e) {
            log.error("Error Redirecting to OIDC Provider End Session Endpoint: {}", e.getMessage());
            redirectToClientOrDefault(oidcLogoutAuthentication, request, response);
        }
    }

    /**
     * Redirect 回 Client 或 錯誤頁面
     */
    private void redirectToClientOrDefault(OidcLogoutAuthenticationToken oidcLogoutAuthentication, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String clientFinalRedirectUri = oidcLogoutAuthentication.getPostLogoutRedirectUri();
        if (StringUtils.hasText(clientFinalRedirectUri)) {
            UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(clientFinalRedirectUri);
            if (StringUtils.hasText(oidcLogoutAuthentication.getState())) {
                uriBuilder.queryParam(StringUtil.STATE, UriUtils.encode(oidcLogoutAuthentication.getState(), StandardCharsets.UTF_8));
            }
            String redirectUri = uriBuilder.build(true).toUriString();
            this.redirectStrategy.sendRedirect(request, response, redirectUri);
        } else {
            redirectToDefaultLogoutPage(request, response);
        }
    }

    /**
     * Redirect 回錯誤頁面
     */
    private void redirectToDefaultLogoutPage(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        SimpleUrlLogoutSuccessHandler fallbackHandler = new SimpleUrlLogoutSuccessHandler();
        fallbackHandler.setDefaultTargetUrl(StringUtil.ERROR_PATH);
        fallbackHandler.onLogoutSuccess(request, response, null);
    }

    private void logLogoutActivityAndRemoveAuthorization(HttpServletRequest request, OAuth2Authorization authorization) {
        // 清理授權數據，紀錄登出活動
        if (authorization != null) {
            // 移除代理層的授權記錄
            // authorizationService.remove(authorization);
            // 記錄登出活動
            authActivityService.save(authorization, request, AuthAction.LOGOUT);
        }
    }

    private OAuth2Authorization getOAuth2Authorization(OidcLogoutAuthenticationToken oidcLogoutAuthentication) {
        String idToken = getIdToken(oidcLogoutAuthentication);

        OAuth2Authorization authorization = null;
        if (idToken != null) {
            authorization = authorizationService.findByToken(
                    idToken, new OAuth2TokenType(StringUtil.ID_TOKEN));
        }

        return authorization;
    }

    private String getIdToken(OidcLogoutAuthenticationToken oidcLogoutAuthentication) {
        try {
            return Objects.requireNonNull(oidcLogoutAuthentication.getIdToken()).getTokenValue();
        } catch (Exception e) {
            log.warn("Cannot get ID Token");
            return null;
        }
    }

    private String getClientRegistrationId(OAuth2Authorization authorization) {
        String clientRegistrationId = null;
        Authentication userAuthentication = (Authentication) authorization.getAttributes().get(Principal.class.getName());
        if (userAuthentication instanceof OAuth2AuthenticationToken oauth2Token) {
            clientRegistrationId = oauth2Token.getAuthorizedClientRegistrationId();
        }

        return clientRegistrationId;
    }

    private String getProviderEndSessionEndpoint(String clientRegistrationId) {
        String endSessionEndpoint = null;

        if (StringUtils.hasText(clientRegistrationId)) {
            ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
            if (clientRegistration != null) {
                Map<String, Object> configurationMetadata = clientRegistration.getProviderDetails().getConfigurationMetadata();
                if (configurationMetadata != null) {
                    Object endpointObj = configurationMetadata.get(StringUtil.END_SESSION_ENDPOINT_ATTR_NAME);
                    if (endpointObj instanceof String) {
                        endSessionEndpoint = (String) endpointObj;
                    }
                }
            }
        }
        return endSessionEndpoint;
    }

    private String getProviderIdToken(OAuth2Authorization authorization) {
        String providerIdToken = null;

        Authentication userPrincipalFromAuthorization = (Authentication) authorization.getAttributes().get(Principal.class.getName());
        if (userPrincipalFromAuthorization instanceof OAuth2AuthenticationToken oauth2AuthToken) {
            if (oauth2AuthToken.getPrincipal() instanceof OidcUserImpl oidcUser) {
                OidcIdToken idToken = oidcUser.getIdToken();
                if (idToken != null) {
                    providerIdToken = idToken.getTokenValue();
                }
            }
        }

        return providerIdToken;
    }

    private String getRedirectUri(OidcLogoutAuthenticationToken oidcLogoutAuthentication) {
        return oidcLogoutAuthentication.getPostLogoutRedirectUri();
    }

}
