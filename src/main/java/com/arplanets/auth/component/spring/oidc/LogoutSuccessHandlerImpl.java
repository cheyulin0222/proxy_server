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
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
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
    private final LogoutSuccessHandler logoutSuccessHandler = createDefaultLogoutSuccessHandler();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OidcLogoutAuthenticationToken oidcLogoutAuthentication = (OidcLogoutAuthenticationToken) authentication;

       // 取得 Local ID Token
        String idToken = Objects.requireNonNull(oidcLogoutAuthentication.getIdToken()).getTokenValue();

        // 清除本地 Session 和 Security Context
        logoutHandler.logout(request, response, (Authentication) oidcLogoutAuthentication.getPrincipal());

        // 取得 redirectUri
        String redirectUri = oidcLogoutAuthentication.getPostLogoutRedirectUri();
        if (!StringUtils.hasText(redirectUri)) {
            // 如果前端 Client 沒有提供最終重定向 URL，則導向你的默認登出頁
            redirectToDefaultLogoutPage(request, response);
            return;
        }

        // 2. 生成 state 並儲存到 Local
        String state = logoutStateRepository.saveLogoutRequest(redirectUri);

        OAuth2Authorization authorization = null;
        if (idToken != null) {
            authorization = authorizationService.findByToken(
                    idToken, new OAuth2TokenType(StringUtil.ID_TOKEN));
        }

        // 3. 清理授權數據，紀錄登出活動
        if (authorization != null) {
             // 移除代理層的授權記錄
//             authorizationService.remove(authorization);
            // 記錄登出活動
            authActivityService.save(authorization, request, AuthAction.LOGOUT);
        } else {
            // 如果找不到 authorization，說明這個 id_token_hint 無效，或用戶從未通過你的代理登錄
            // 這種情況下，直接重定向到 Client 的 post_logout_redirect_uri 或默認頁面
            // 有問題吧!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            redirectToClientOrDefault(oidcLogoutAuthentication, request, response);
            return;
        }



        // 4. 嘗試發起對上游 OIDC Provider 的登出
        String clientRegistrationId = null;
        Authentication userAuthentication = (Authentication) authorization.getAttributes().get(Principal.class.getName());
        if (userAuthentication instanceof OAuth2AuthenticationToken oauth2Token) {
            clientRegistrationId = oauth2Token.getAuthorizedClientRegistrationId();
        }

        log.info("ClientRegistrationId={}", clientRegistrationId);

        String endSessionEndpoint = null;
        if (StringUtils.hasText(clientRegistrationId)) {
            ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
            if (clientRegistration != null) {
                Map<String, Object> configurationMetadata = clientRegistration.getProviderDetails().getConfigurationMetadata();
                if (configurationMetadata != null) {
                    Object endpointObj = configurationMetadata.get("end_session_endpoint");
                    if (endpointObj instanceof String) {
                        endSessionEndpoint = (String) endpointObj;
                    }
                }
            }
        }

        log.info("endSessionEndpoint={}", endSessionEndpoint);

        if (!StringUtils.hasText(endSessionEndpoint)) {
            log.error("Warning: Upstream OIDC Provider '{}' does not expose end_session_endpoint via Discovery or it's not configured. Skipping upstream logout.", clientRegistrationId);
            redirectToClientOrDefault(oidcLogoutAuthentication, request, response);
            return;
        }

        String providerIdToken = null;
        Authentication userPrincipalFromAuthorization = (Authentication) authorization.getAttributes().get(Principal.class.getName());
        if (userPrincipalFromAuthorization instanceof OAuth2AuthenticationToken oauth2AuthToken) {
            if (oauth2AuthToken.getPrincipal() instanceof OidcUserImpl oidcUser) {
                OidcIdToken idToken1 = oidcUser.getIdToken();
                if (idToken1 != null) {
                    providerIdToken = idToken1.getTokenValue();
                } else {
                    log.error("ID Token from OAuth2Authorization is null.");
                }
            } else {
                log.error("OAuth2AuthenticationToken's principal is not an instance of OidcUserImpl.");
            }
        } else {
            log.error("User principal from OAuth2Authorization is not an OAuth2AuthenticationToken.");
        }

        log.debug("providerIdToken={}", providerIdToken);

        if (!StringUtils.hasText(providerIdToken)) {
            log.error("Warning: No upstream IdToken found in authorization for upstream logout. Skipping upstream logout.");
            redirectToClientOrDefault(oidcLogoutAuthentication, request, response);
            return;
        }

        // 構建重定向到你應用程式的回調 URL，並帶上 state
        String providerPostLogoutRedirectUri = UriComponentsBuilder.fromUriString(request.getRequestURL().toString())
                .replacePath("/logout/callback")
                .queryParam("state", state)
                .build().toUriString();


        try {
            // 4. 重定向到上游 OIDC Provider
            providerLogoutService.initiateLogout(
                    endSessionEndpoint,
                    providerIdToken,
                    providerPostLogoutRedirectUri,
                    request,
                    response);
        } catch (Exception e) {
            // 捕獲 initiateLogout 中可能拋出的任何異常（例如，URL 格式錯誤，但不包含 HTTP 連接錯誤）
            System.err.println("Error initiating logout to upstream OIDC Provider: " + e.getMessage());
            // **重定向失敗，將用戶導向前端 Client 的最終重定向 URL**
            redirectToClientOrDefault(oidcLogoutAuthentication, request, response);
        }
    }



    private LogoutSuccessHandler createDefaultLogoutSuccessHandler() {
        SimpleUrlLogoutSuccessHandler handler = new SimpleUrlLogoutSuccessHandler();
        handler.setDefaultTargetUrl(StringUtil.ROOT_PATH);
        return handler;
    }

    // 輔助方法，用於統一處理重定向到 Client 或默認頁面
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

    private void redirectToDefaultLogoutPage(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        // 這裡可以導向一個固定的「登出失敗/部分登出」頁面
        // 而不是簡單的 ROOT_PATH
        SimpleUrlLogoutSuccessHandler fallbackHandler = new SimpleUrlLogoutSuccessHandler();
        fallbackHandler.setDefaultTargetUrl("/logout-fallback"); // 比如一個專門的頁面
        fallbackHandler.onLogoutSuccess(request, response, null);
    }
}
