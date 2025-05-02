package com.arplanets.auth.handler;

import com.arplanets.auth.model.enums.AuthAction;
import com.arplanets.auth.service.AuthActivityService;
import com.arplanets.auth.utils.StringUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
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
import java.util.Objects;

@RequiredArgsConstructor
public class LogoutSuccessHandlerImpl implements AuthenticationSuccessHandler {

    private final AuthActivityService authActivityService;
    private final OAuth2AuthorizationService authorizationService;
    private final LogoutHandler logoutHandler = new SecurityContextLogoutHandler();
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final LogoutSuccessHandler logoutSuccessHandler = createDefaultLogoutSuccessHandler();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OidcLogoutAuthenticationToken oidcLogoutAuthentication = (OidcLogoutAuthenticationToken) authentication;

        String idToken = Objects.requireNonNull(oidcLogoutAuthentication.getIdToken()).getTokenValue();

        if (idToken != null) {
            OAuth2Authorization authorization = authorizationService.findByToken(
                    idToken, new OAuth2TokenType(StringUtil.ID_TOKEN));

            if (authorization != null) {
                // 記錄登出活動
                authActivityService.save(authorization, request, AuthAction.LOGOUT);
            }
        }

        // Perform default logout behavior
        if (oidcLogoutAuthentication.isPrincipalAuthenticated() && StringUtils.hasText(oidcLogoutAuthentication.getSessionId())) {
            this.logoutHandler.logout(request, response, (Authentication) oidcLogoutAuthentication.getPrincipal());
        }

        if (oidcLogoutAuthentication.isAuthenticated() && StringUtils.hasText(oidcLogoutAuthentication.getPostLogoutRedirectUri())) {
            UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(oidcLogoutAuthentication.getPostLogoutRedirectUri());
            if (StringUtils.hasText(oidcLogoutAuthentication.getState())) {
                uriBuilder.queryParam(StringUtil.STATE, UriUtils.encode(oidcLogoutAuthentication.getState(), StandardCharsets.UTF_8));
            }

            String redirectUri = uriBuilder.build(true).toUriString();
            this.redirectStrategy.sendRedirect(request, response, redirectUri);
        } else {
            this.logoutSuccessHandler.onLogoutSuccess(request, response, (Authentication) oidcLogoutAuthentication.getPrincipal());
        }

    }

    private LogoutSuccessHandler createDefaultLogoutSuccessHandler() {
        SimpleUrlLogoutSuccessHandler handler = new SimpleUrlLogoutSuccessHandler();
        handler.setDefaultTargetUrl(StringUtil.ROOT_PATH);
        return handler;
    }
}
