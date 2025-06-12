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

        try {
            OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

            // 取得 Authorization Code
            String authorizationCode = getAuthorizationCode(authenticationToken);

            // 紀錄登入狀態，以及儲存 Session ID (登出用)
            updateAndSaveAuthorization(request, authorizationCode);

            // 導轉
            redirectToClient(request, response, authenticationToken, authorizationCode);

        } catch (Exception e) {
            log.error("Error during authentication success handling.", e);
            throw new IOException("Failed to handle authentication success.", e);
        }
    }

    /**
     * 紀錄登入狀態，以及儲存 Session ID (登出用)
     */
    private void updateAndSaveAuthorization(HttpServletRequest request, String authorizationCode) {

        // 取得授權資料
        OAuth2Authorization authorization = authorizationService.findByToken(
                authorizationCode, new OAuth2TokenType(StringUtil.CODE));

        if (authorization != null) {

            // 儲存 Session ID 資料
            authorization = OAuth2Authorization.from(authorization)
                    .attribute(StringUtil.AUTH_SESSION_ID, getSessionId(request))
                    .build();
            authorizationService.save(authorization);

            // 紀錄登入狀態
            authActivityService.save(authorization, request, AuthAction.LOGIN);
        } else {
            log.warn("OAuth2Authorization not found during login activity logging. This might indicate an issue with the authorization flow.");
        }
    }

    private void redirectToClient(HttpServletRequest request, HttpServletResponse response,
                                  OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
                                  String authorizationCode) throws IOException {

        // 取得路徑
        String redirectUri = Objects.requireNonNull(
                authorizationCodeRequestAuthentication.getRedirectUri(),
                "Redirect URI cannot be null for successful authorization."
        );

        // 帶入 Code 參數
        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam(StringUtil.CODE, authorizationCode);

        // 帶入 State 參數
        if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
            uriBuilder.queryParam(StringUtil.STATE,
                    UriUtils.encode(authorizationCodeRequestAuthentication.getState(), StandardCharsets.UTF_8));
        }

        String finalRedirectUri = uriBuilder.build(true).toUriString();

        log.info("Redirecting to client application: {}", redirectUri);
        this.redirectStrategy.sendRedirect(request, response, finalRedirectUri);
    }

    private String getAuthorizationCode(OAuth2AuthorizationCodeRequestAuthenticationToken authenticationToken) {
        return Objects.requireNonNull(
                authenticationToken.getAuthorizationCode(),
                "Authorization Code cannot be null after successful authentication."
        ).getTokenValue();
    }

    private String getSessionId(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        String sessionId = (session != null) ? session.getId() : null;
        log.debug("Session ID after code generation: {}", sessionId);
        return sessionId;
    }
}
