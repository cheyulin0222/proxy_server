package com.arplanets.auth.handler;

import com.arplanets.auth.model.enums.AuthAction;
import com.arplanets.auth.service.AuthActivityService;
import com.arplanets.auth.utils.StringUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

@RequiredArgsConstructor
@Slf4j
public class AuthorizationSuccessHandlerImpl implements AuthenticationSuccessHandler {

    private final AuthActivityService authActivityService;
    private final OAuth2AuthorizationService authorizationService;
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = (OAuth2AuthorizationCodeRequestAuthenticationToken)authentication;


        String authorizationCode = Objects.requireNonNull(authorizationCodeRequestAuthentication.getAuthorizationCode()).getTokenValue();

        // 處理登入日誌記錄
        try {
            OAuth2Authorization authorization = authorizationService.findByToken(
                    authorizationCode, new OAuth2TokenType(StringUtil.CODE));

            if (authorization != null) {
                authActivityService.save(authorization, request, AuthAction.LOGIN);
            } else {
                log.warn("OAuth2Authorization not found for code '{}' during logging.", authorizationCode);
            }
        } catch (Exception ex) {
            log.error("Failed to log login activity for authorization code '{}'. Continuing with redirect.", authorizationCode, ex);
        }


        // 執行重導向
        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(Objects.requireNonNull(authorizationCodeRequestAuthentication.getRedirectUri())).queryParam("code", authorizationCode);
        if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
            uriBuilder.queryParam(StringUtil.STATE, UriUtils.encode(authorizationCodeRequestAuthentication.getState(), StandardCharsets.UTF_8));
        }

        String redirectUri = uriBuilder.build(true).toUriString();
        this.redirectStrategy.sendRedirect(request, response, redirectUri);
    }
}
