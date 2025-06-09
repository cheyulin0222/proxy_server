package com.arplanets.auth.component.spring.oidc;

import com.arplanets.auth.model.enums.AuthAction;
import com.arplanets.auth.service.persistence.impl.AuthActivityService;
import com.arplanets.auth.utils.StringUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * 記錄登入資訊
 */
@RequiredArgsConstructor
@Slf4j
public class AuthorizationSuccessHandlerImpl implements AuthenticationSuccessHandler {

    private final AuthActivityService authActivityService;
    private final OAuth2AuthorizationService authorizationService;
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication;
        HttpSession currentAuthenticatedSession = null;
        String currentSessionId = null;

        try {
            if (!(authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken)) {
                log.error("Authentication token is not OAuth2AuthorizationCodeRequestAuthenticationToken: {}", authentication.getClass().getName());
                throw new IllegalStateException("Unexpected authentication token type.");
            }

            authorizationCodeRequestAuthentication = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

            // 取得 Code
            String authorizationCode = Objects.requireNonNull(
                    authorizationCodeRequestAuthentication.getAuthorizationCode(),
                    "Authorization Code cannot be null after successful authentication."
            ).getTokenValue();

            // 取得 SessionId
            currentAuthenticatedSession = request.getSession(false);
            if (currentAuthenticatedSession != null) {
                currentSessionId = currentAuthenticatedSession.getId();
            }

            log.debug("Session ID after code generation: {}", currentSessionId);

            // 取得當前授權資料
            OAuth2Authorization authorization = authorizationService.findByToken(
                    authorizationCode, new OAuth2TokenType(StringUtil.CODE));

            if (authorization != null) {
                authorization = OAuth2Authorization.from(authorization)
                        .attribute("authenticated_session_id", currentSessionId)
                        .build();

                // 儲存 SessionId 用於登出
                authorizationService.save(authorization);
                // 記錄登入狀態
                authActivityService.save(authorization, request, AuthAction.LOGIN);

            } else {
                log.error("OAuth2Authorization not found for code '{}' during login activity logging. This might indicate an issue with the authorization flow.", authorizationCode);
            }
        } catch (Exception e) {
            log.warn("Failed to log login activity or update OAuth2Authorization due to an exception. Continuing with redirect.", e);
            throw e;
        } finally {
            if (currentAuthenticatedSession != null) {
                currentAuthenticatedSession.removeAttribute("UPSTREAM_ID_TOKEN");
                log.debug("Removed 'UPSTREAM_ID_TOKEN' from session in finally block.");
            } else {
                log.debug("No active session available to remove 'UPSTREAM_ID_TOKEN' from in finally block.");
            }
        }

        // Get the redirect URI from the authentication request.
        String redirectUri = Objects.requireNonNull(
                authorizationCodeRequestAuthentication.getRedirectUri(),
                "Redirect URI cannot be null for successful authorization."
        );

        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("code", authorizationCodeRequestAuthentication.getAuthorizationCode().getTokenValue());

        if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
            uriBuilder.queryParam(StringUtil.STATE,
                    UriUtils.encode(authorizationCodeRequestAuthentication.getState(), StandardCharsets.UTF_8));
        }

        String finalRedirectUri = uriBuilder.build(true).toUriString();

        log.debug("Redirecting to client application: {}", finalRedirectUri);
        this.redirectStrategy.sendRedirect(request, response, finalRedirectUri);
    }
}
